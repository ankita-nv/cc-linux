// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 ARM Ltd.
 */
#include <linux/module.h>
#include <linux/slab.h>

#include "iommufd_private.h"

static LIST_HEAD(viommu_providers);
static DEFINE_MUTEX(viommu_providers_lock);

static struct iommufd_viommu_provider *
viommu_find_provider(enum iommu_viommu_type type)
{
	struct iommufd_viommu_provider *provider;

	lockdep_assert_held(&viommu_providers_lock);
	list_for_each_entry(provider, &viommu_providers, node)
		if (provider->ops->type == type)
			return provider;
	return NULL;
}

static void viommu_provider_put(struct iommufd_viommu_provider *provider)
{
	if (!refcount_dec_and_test(&provider->users))
		return;
	if (provider->ops->release)
		provider->ops->release(provider->data);
	kfree(provider);
}

void iommufd_put_viommu_provider(struct iommufd_viommu_provider *provider)
{
	struct module *owner;

	if (!provider)
		return;

	owner = provider->owner;
	viommu_provider_put(provider);
	module_put(owner);
}

/**
 * iommufd_register_viommu_provider() - Register an external vIOMMU provider
 * @ops: Provider operations, including its module owner and exact type
 * @data: Private data to retain until the final provider release
 *
 * Only one provider may be registered per type. ops->release() is called
 * after unregister and the last vIOMMU release. Registration itself does
 * not pin the module; each allocation does.
 *
 * Return: Registration handle or ERR_PTR() on failure.
 */
struct iommufd_viommu_provider *
iommufd_register_viommu_provider(const struct iommufd_viommu_provider_ops *ops,
	    void *data)
{
	struct iommufd_viommu_provider *provider;

	if (ops->type == IOMMU_VIOMMU_TYPE_DEFAULT ||
	    !ops->get_size || !ops->init)
		return ERR_PTR(-EINVAL);

	provider = kzalloc_obj(*provider);
	if (!provider)
		return ERR_PTR(-ENOMEM);
	provider->ops = ops;
	provider->owner = ops->owner;
	provider->data = data;
	refcount_set(&provider->users, 1);

	mutex_lock(&viommu_providers_lock);
	if (viommu_find_provider(ops->type)) {
		mutex_unlock(&viommu_providers_lock);
		kfree(provider);
		return ERR_PTR(-EBUSY);
	}
	list_add_tail(&provider->node, &viommu_providers);
	mutex_unlock(&viommu_providers_lock);
	return provider;
}
EXPORT_SYMBOL_NS_GPL(iommufd_register_viommu_provider, "IOMMUFD");

/**
 * iommufd_unregister_viommu_provider() - Stop new lookups of a provider
 * @provider: Handle returned by iommufd_register_viommu_provider()
 *
 * Call once per registration. Existing vIOMMUs retain the operations,
 * private data and module until destruction. This does not wait for them
 * to be released.
 */
void iommufd_unregister_viommu_provider(struct iommufd_viommu_provider *provider)
{
	mutex_lock(&viommu_providers_lock);
	list_del(&provider->node);
	mutex_unlock(&viommu_providers_lock);
	viommu_provider_put(provider);
}
EXPORT_SYMBOL_NS_GPL(iommufd_unregister_viommu_provider, "IOMMUFD");

static size_t fallback_viommu_get_size(struct device *dev,
		enum iommu_viommu_type type)
{
	return dev_iommu_ops(dev)->get_viommu_size(dev, type);
}

static int fallback_viommu_init(struct iommufd_viommu *viommu,
		struct device *dev, struct iommu_domain *parent,
		const struct iommu_user_data *user_data)
{
	const struct iommu_ops *ops = viommu->provider_data;

	return ops->viommu_init(viommu, parent, user_data);
}

static const struct iommufd_viommu_provider_ops fallback_viommu_provider_ops = {
	.get_size = fallback_viommu_get_size,
	.init = fallback_viommu_init,
};

struct iommufd_viommu_provider *
iommufd_get_viommu_provider(struct device *dev, enum iommu_viommu_type type)
{
	const struct iommu_ops *iommu_ops;
	struct iommufd_viommu_provider *provider;

	mutex_lock(&viommu_providers_lock);
	provider = viommu_find_provider(type);
	if (provider) {
		if (!try_module_get(provider->owner)) {
			mutex_unlock(&viommu_providers_lock);
			return ERR_PTR(-ENODEV);
		}
		refcount_inc(&provider->users);
		mutex_unlock(&viommu_providers_lock);
		return provider;
	}
	mutex_unlock(&viommu_providers_lock);

	iommu_ops = dev_iommu_ops(dev);
	if (!iommu_ops->get_viommu_size || !iommu_ops->viommu_init)
		return ERR_PTR(-EOPNOTSUPP);
	if (!try_module_get(iommu_ops->owner))
		return ERR_PTR(-ENODEV);

	provider = kzalloc_obj(*provider);
	if (!provider) {
		module_put(iommu_ops->owner);
		return ERR_PTR(-ENOMEM);
	}
	provider->ops = &fallback_viommu_provider_ops;
	provider->owner = iommu_ops->owner;
	provider->data = (void *)iommu_ops;
	refcount_set(&provider->users, 1);
	return provider;
}

