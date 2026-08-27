use navigator_domain::{
    AuthorityCeilings, AuthorityError, AuthorityOrigin, AuthorityProfile, Capability, Grant,
    GrantId, ParticipantId, ResourceScope, ScopedCapability, SessionId, Timestamp,
};
use uuid::Uuid;

fn id<T>(
    value: u128,
    make: impl FnOnce(Uuid) -> Result<T, navigator_domain::InvalidIdentity>,
) -> T {
    make(Uuid::from_u128(value)).unwrap()
}

fn rule(name: &str, participant: ParticipantId) -> ScopedCapability {
    ScopedCapability::new(
        Capability::new(name).unwrap(),
        ResourceScope::Participant(participant),
    )
}

fn profile(active: &[ScopedCapability], delegable: &[ScopedCapability]) -> AuthorityProfile {
    AuthorityProfile::new(active.to_vec(), delegable.to_vec()).unwrap()
}

fn ceilings<'a>(
    session: &'a AuthorityProfile,
    parent: &'a AuthorityProfile,
    template: &'a AuthorityProfile,
    relationship: &'a AuthorityProfile,
    subject: &'a AuthorityProfile,
) -> AuthorityCeilings<'a> {
    AuthorityCeilings {
        session,
        parent,
        template,
        relationship,
        subject,
    }
}

#[test]
fn every_creation_ceiling_is_an_independent_intersection_operand() {
    let participant = id(1, ParticipantId::from_uuid);
    let requested = rule("artifact.publish", participant);
    let allow = profile(&[], std::slice::from_ref(&requested));
    assert!(
        ceilings(&allow, &allow, &allow, &allow, &allow)
            .authorize_child_creation(&requested)
            .is_ok()
    );

    for denied_layer in 0..5 {
        let deny = profile(&[], &[]);
        let layers = [&allow, &allow, &allow, &allow, &allow];
        let mut mutant = layers;
        mutant[denied_layer] = &deny;
        assert_eq!(
            ceilings(mutant[0], mutant[1], mutant[2], mutant[3], mutant[4])
                .authorize_child_creation(&requested),
            Err(AuthorityError::Denied),
            "layer {denied_layer} was not part of the delegation intersection"
        );
    }
}

#[test]
fn parent_can_delegate_without_active_possession_but_cannot_delegate_beyond_its_ceiling() {
    let participant = id(2, ParticipantId::from_uuid);
    let requested = rule("tool.search", participant);
    let active_and_delegable = profile(
        std::slice::from_ref(&requested),
        std::slice::from_ref(&requested),
    );
    let delegate_only = profile(&[], std::slice::from_ref(&requested));
    assert!(
        ceilings(
            &active_and_delegable,
            &delegate_only,
            &active_and_delegable,
            &active_and_delegable,
            &active_and_delegable,
        )
        .authorize_child_creation(&requested)
        .is_ok()
    );
    let no_delegation = profile(std::slice::from_ref(&requested), &[]);
    assert_eq!(
        ceilings(
            &active_and_delegable,
            &no_delegation,
            &active_and_delegable,
            &active_and_delegable,
            &active_and_delegable,
        )
        .authorize_child_creation(&requested),
        Err(AuthorityError::Denied)
    );
}

#[test]
fn effect_time_rechecks_active_and_delegable_axes_and_explains_every_origin() {
    let session_id = id(3, SessionId::from_uuid);
    let participant = id(4, ParticipantId::from_uuid);
    let requested = rule("artifact.read", participant);
    let full = profile(
        std::slice::from_ref(&requested),
        std::slice::from_ref(&requested),
    );
    let parent = profile(&[], std::slice::from_ref(&requested));
    let decision = ceilings(&full, &parent, &full, &full, &full)
        .authorize_effect(
            participant,
            session_id,
            &requested,
            None,
            Timestamp::new(10, 0).unwrap(),
        )
        .unwrap();
    assert_eq!(decision.authority, requested);
    assert_eq!(decision.origins.len(), 5);
    assert!(
        decision
            .origins
            .contains(&AuthorityOrigin::ParentDelegation)
    );

    let inactive = profile(&[], std::slice::from_ref(&requested));
    assert_eq!(
        ceilings(&full, &parent, &inactive, &full, &full).authorize_effect(
            participant,
            session_id,
            &requested,
            None,
            Timestamp::new(10, 0).unwrap(),
        ),
        Err(AuthorityError::Denied)
    );
}

#[test]
fn grant_identity_scope_expiry_and_revocation_are_checked_at_effect_time() {
    let session_id = id(5, SessionId::from_uuid);
    let participant = id(6, ParticipantId::from_uuid);
    let requested = rule("network.send", participant);
    let full = profile(
        std::slice::from_ref(&requested),
        std::slice::from_ref(&requested),
    );
    let grant = Grant {
        id: id(7, GrantId::from_uuid),
        session_id,
        subject: participant,
        authority: requested.clone(),
        expires_at: Timestamp::new(20, 0).unwrap(),
        revoked: false,
    };
    let policy = ceilings(&full, &full, &full, &full, &full);
    let allowed = policy
        .authorize_effect(
            participant,
            session_id,
            &requested,
            Some(&grant),
            Timestamp::new(19, 999_999_999).unwrap(),
        )
        .unwrap();
    assert!(allowed.origins.contains(&AuthorityOrigin::Grant(grant.id)));
    assert_eq!(
        policy.authorize_effect(
            participant,
            session_id,
            &requested,
            Some(&grant),
            Timestamp::new(20, 0).unwrap(),
        ),
        Err(AuthorityError::Denied)
    );
    let mut revoked = grant.clone();
    revoked.revoked = true;
    assert_eq!(
        policy.authorize_effect(
            participant,
            session_id,
            &requested,
            Some(&revoked),
            Timestamp::new(19, 0).unwrap(),
        ),
        Err(AuthorityError::Denied)
    );
    let mut forged = grant;
    forged.subject = id(8, ParticipantId::from_uuid);
    assert_eq!(
        policy.authorize_effect(
            participant,
            session_id,
            &requested,
            Some(&forged),
            Timestamp::new(19, 0).unwrap(),
        ),
        Err(AuthorityError::Denied)
    );
}

#[test]
fn typed_resource_and_duplicate_or_oversized_rules_fail_closed() {
    let participant = id(9, ParticipantId::from_uuid);
    let other = id(10, ParticipantId::from_uuid);
    let requested = rule("tool.execute", participant);
    let wrong_resource = rule("tool.execute", other);
    let allow = profile(
        std::slice::from_ref(&wrong_resource),
        std::slice::from_ref(&wrong_resource),
    );
    assert_eq!(
        ceilings(&allow, &allow, &allow, &allow, &allow).authorize_effect(
            participant,
            id(11, SessionId::from_uuid),
            &requested,
            None,
            Timestamp::new(1, 0).unwrap(),
        ),
        Err(AuthorityError::Denied)
    );
    assert_eq!(
        AuthorityProfile::new([requested.clone(), requested.clone()], []),
        Err(AuthorityError::DuplicateRule)
    );
    assert_eq!(
        AuthorityProfile::new(
            (0..=navigator_domain::MAX_AUTHORITY_RULES).map(|index| {
                rule(
                    &format!("tool.{index}"),
                    id(
                        u128::try_from(index + 100).unwrap(),
                        ParticipantId::from_uuid,
                    ),
                )
            }),
            [],
        ),
        Err(AuthorityError::TooManyRules)
    );
}
