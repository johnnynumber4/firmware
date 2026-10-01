#include "configuration.h"

#include "HostedIdentities.h"

#include "CryptoEngine.h"
#include "NodeDB.h"
#include <ErriezCRC32.h>
#include <cstring>

namespace hosted
{

namespace
{

/** Copy a name into a fixed buffer, keeping it terminated and whole UTF-8 characters. */
void copyName(char *dest, size_t size, const char *src)
{
    if (!src)
        src = "";
    size_t n = strnlen(src, size - 1);
    // Don't cut a multi-byte character in half.
    while (n > 0 && n < strlen(src) && (static_cast<unsigned char>(src[n]) & 0xC0) == 0x80)
        n--;
    memcpy(dest, src, n);
    dest[n] = '\0';
}

void applyNames(meshtastic_HostedIdentityKeys &identity, const char *longName, const char *shortName)
{
    char fallbackLong[sizeof(identity.long_name)];
    char fallbackShort[sizeof(identity.short_name)];
    snprintf(fallbackLong, sizeof(fallbackLong), "Meshtastic %04x", identity.num & 0xffff);
    snprintf(fallbackShort, sizeof(fallbackShort), "%04x", identity.num & 0xffff);
    copyName(identity.long_name, sizeof(identity.long_name), longName && *longName ? longName : fallbackLong);
    copyName(identity.short_name, sizeof(identity.short_name), shortName && *shortName ? shortName : fallbackShort);
}

meshtastic_HostedIdentityKeys *findMutable(NodeNum num)
{
    if (num == 0)
        return nullptr;
    for (pb_size_t i = 0; i < devicestate.hosted_identities_count; i++) {
        if (devicestate.hosted_identities[i].num == num)
            return &devicestate.hosted_identities[i];
    }
    return nullptr;
}

/** Numbers the mesh never assigns to a node, as NodeDB's NUM_RESERVED. */
constexpr NodeNum RESERVED_NUMBERS = 4;

/** A number another node already uses, or one the mesh reserves, can't be an identity. */
bool numberTaken(NodeNum num)
{
    if (num < RESERVED_NUMBERS || num == NODENUM_BROADCAST || num == NODENUM_BROADCAST_NO_LORA || num == nodeDB->getNodeNum())
        return true;
    if (findMutable(num))
        return true;
    return nodeDB->getMeshNode(num) != nullptr;
}

void save()
{
    nodeDB->saveToDisk(SEGMENT_DEVICESTATE);
}

} // namespace

const meshtastic_HostedIdentityKeys *find(NodeNum num)
{
    return findMutable(num);
}

bool isHosted(NodeNum num)
{
    return findMutable(num) != nullptr;
}

NodeNum create(const char *longName, const char *shortName)
{
#if MESHTASTIC_EXCLUDE_PKI || MESHTASTIC_EXCLUDE_PKI_KEYGEN
    (void)longName;
    (void)shortName;
    return 0;
#else
    if (devicestate.hosted_identities_count >= MAX_IDENTITIES)
        return 0;
    meshtastic_HostedIdentityKeys identity = meshtastic_HostedIdentityKeys_init_zero;
    // A number derived from a fresh key almost never clashes; retry the rare one that does.
    for (int attempt = 0; attempt < 8; attempt++) {
        if (!crypto->generateDetachedKeyPair(identity.public_key.bytes, identity.private_key.bytes))
            continue;
        identity.public_key.size = 32;
        identity.private_key.size = 32;
        identity.num = crc32Buffer(identity.public_key.bytes, identity.public_key.size);
        if (!numberTaken(identity.num))
            break;
        identity.num = 0;
    }
    if (identity.num == 0)
        return 0;
    applyNames(identity, longName, shortName);
    devicestate.hosted_identities[devicestate.hosted_identities_count++] = identity;
    save();
    LOG_INFO("Hosted identity 0x%08x created: %s/%s", identity.num, identity.long_name, identity.short_name);
    return identity.num;
#endif
}

bool rename(NodeNum num, const char *longName, const char *shortName)
{
    meshtastic_HostedIdentityKeys *identity = findMutable(num);
    if (!identity)
        return false;
    applyNames(*identity, longName, shortName);
    save();
    return true;
}

bool remove(NodeNum num)
{
    for (pb_size_t i = 0; i < devicestate.hosted_identities_count; i++) {
        if (devicestate.hosted_identities[i].num != num)
            continue;
        for (pb_size_t j = i + 1; j < devicestate.hosted_identities_count; j++)
            devicestate.hosted_identities[j - 1] = devicestate.hosted_identities[j];
        devicestate.hosted_identities_count--;
        // Don't leave a private key behind in the unused slot.
        devicestate.hosted_identities[devicestate.hosted_identities_count] = meshtastic_HostedIdentityKeys_init_zero;
        save();
        LOG_INFO("Hosted identity 0x%08x removed", num);
        return true;
    }
    return false;
}

void list(meshtastic_HostedIdentities &out)
{
    out = meshtastic_HostedIdentities_init_zero;
    for (pb_size_t i = 0; i < devicestate.hosted_identities_count && i < MAX_IDENTITIES; i++) {
        const meshtastic_HostedIdentityKeys &src = devicestate.hosted_identities[i];
        meshtastic_HostedIdentity &dst = out.identities[out.identities_count++];
        dst.num = src.num;
        strncpy(dst.long_name, src.long_name, sizeof(dst.long_name) - 1);
        strncpy(dst.short_name, src.short_name, sizeof(dst.short_name) - 1);
        dst.public_key.size = src.public_key.size;
        memcpy(dst.public_key.bytes, src.public_key.bytes, src.public_key.size);
    }
}

meshtastic_User userFor(const meshtastic_HostedIdentityKeys &identity)
{
    meshtastic_User user = meshtastic_User_init_zero;
    snprintf(user.id, sizeof(user.id), "!%08x", identity.num);
    strncpy(user.long_name, identity.long_name, sizeof(user.long_name) - 1);
    strncpy(user.short_name, identity.short_name, sizeof(user.short_name) - 1);
    // Same radio, same hardware and role; receivers reject a licensed mismatch.
    user.hw_model = owner.hw_model;
    user.role = owner.role;
    user.is_licensed = owner.is_licensed;
    user.public_key.size = identity.public_key.size;
    memcpy(user.public_key.bytes, identity.public_key.bytes, identity.public_key.size);
    return user;
}

KeyScope::KeyScope(NodeNum num)
{
#if !(MESHTASTIC_EXCLUDE_PKI)
    const meshtastic_HostedIdentityKeys *identity = find(num);
    if (identity && identity->private_key.size == 32) {
        crypto->selectDHPrivateKey(identity->private_key.bytes);
        switched = true;
    }
#else
    (void)num;
#endif
}

KeyScope::~KeyScope()
{
#if !(MESHTASTIC_EXCLUDE_PKI)
    if (switched)
        crypto->selectDHPrivateKey(config.security.private_key.bytes);
#endif
}

} // namespace hosted
