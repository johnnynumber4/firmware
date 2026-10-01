#pragma once

#include "MeshTypes.h"
#include "mesh/generated/meshtastic/admin.pb.h"
#include "mesh/generated/meshtastic/deviceonly.pb.h"
#include "mesh/generated/meshtastic/mesh.pb.h"

/**
 * Hosted identities: extra nodes this radio sends and receives as, so several
 * people sharing one radio each appear on the mesh as their own node.
 *
 * Each identity has its own key pair, and its node number is derived from its
 * public key exactly as this radio's own is, so it can't collide with or
 * impersonate another node. The private keys live in DeviceState and never
 * leave the radio. See AdminMessage.set_hosted_identity.
 */
namespace hosted
{

/** The most identities one radio hosts: DeviceState.hosted_identities' max_count. */
constexpr size_t MAX_IDENTITIES = sizeof(meshtastic_DeviceState::hosted_identities) / sizeof(meshtastic_HostedIdentityKeys);

/** The identity with this node number, or nullptr. */
const meshtastic_HostedIdentityKeys *find(NodeNum num);

/** Whether this radio hosts `num`. Cheap enough for isFromUs()/isToUs(). */
bool isHosted(NodeNum num);

/** Create an identity and save it. Returns its node number, or 0 if none is free or key generation failed. */
NodeNum create(const char *longName, const char *shortName);

/** Rename an identity and save it. False if there's no such identity. */
bool rename(NodeNum num, const char *longName, const char *shortName);

/** Remove an identity and save. False if there's no such identity. */
bool remove(NodeNum num);

/** The public parts of every identity, for get_hosted_identities_response. */
void list(meshtastic_HostedIdentities &out);

/** The identity as its NodeInfo announces it. */
meshtastic_User userFor(const meshtastic_HostedIdentityKeys &identity);

/**
 * While alive, the crypto engine signs, encrypts and decrypts as `num` if this
 * radio hosts it, and as itself otherwise. Construct while holding cryptLock.
 */
class KeyScope
{
  public:
    explicit KeyScope(NodeNum num);
    ~KeyScope();
    KeyScope(const KeyScope &) = delete;
    KeyScope &operator=(const KeyScope &) = delete;

  private:
    bool switched = false;
};

} // namespace hosted
