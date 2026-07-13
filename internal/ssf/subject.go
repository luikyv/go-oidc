package ssf

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type requestSubject struct {
	StreamID string           `json:"stream_id"`
	Subject  goidc.SSFSubject `json:"subject"`
	Verified *bool            `json:"verified,omitempty"`
}

func addSubject(ctx oidc.Context, req requestSubject) error {
	stream, _, err := authorizedStream(ctx, req.StreamID)
	if err != nil {
		return err
	}

	if err := validateSubject(ctx, req.Subject); err != nil {
		return goidc.Errorf(goidc.ErrorCodeInvalidRequest, "invalid subject: %s", err.Error())
	}

	// The verified request field is optional. When omitted, event transmitters
	// should assume that the receiver has verified the subject claim.
	// See [SSF 1.0 §8.1.3.2].
	verified := true
	if req.Verified != nil {
		verified = *req.Verified
	}
	if err := ctx.SSFAddSubject(stream.ID, req.Subject, goidc.SSFSubjectOptions{
		Verified: verified,
	}); err != nil {
		return fmt.Errorf("could not add the subject to the event stream: %w", err)
	}

	if ctx.SSFInactivityTimeoutSecs > 0 && stream.Status == goidc.SSFStreamStatusEnabled {
		stream.InactiveAt = timeutil.TimestampNow() + ctx.SSFInactivityTimeoutSecs
		if err := ctx.SSFSaveStream(stream); err != nil {
			return fmt.Errorf("could not save stream: %w", err)
		}
	}

	return nil
}

func removeSubject(ctx oidc.Context, req requestSubject) error {
	stream, _, err := authorizedStream(ctx, req.StreamID)
	if err != nil {
		return err
	}

	if err := validateSubject(ctx, req.Subject); err != nil {
		return goidc.Errorf(goidc.ErrorCodeInvalidRequest, "invalid subject: %s", err.Error())
	}

	if err := ctx.SSFRemoveSubject(req.StreamID, req.Subject); err != nil {
		return fmt.Errorf("could not remove the subject from the event stream: %w", err)
	}

	if ctx.SSFInactivityTimeoutSecs > 0 && stream.Status == goidc.SSFStreamStatusEnabled {
		stream.InactiveAt = timeutil.TimestampNow() + ctx.SSFInactivityTimeoutSecs
		if err := ctx.SSFSaveStream(stream); err != nil {
			return fmt.Errorf("could not save stream: %w", err)
		}
	}

	return nil
}

// CompareSubjects compares two [goidc.SSFSubject] according to the subject matching rules.
// [SSF 1.0 §8.1.3.1].
func CompareSubjects(ctx oidc.Context, a, b goidc.SSFSubject) error {
	return compareSubjects(ctx, &a, &b)
}

func compareSubjects(ctx oidc.Context, a, b *goidc.SSFSubject) error {
	if a != nil {
		if err := validateSubject(ctx, *a); err != nil {
			return fmt.Errorf("invalid subject: %w", err)
		}
	}

	if b != nil {
		if err := validateSubject(ctx, *b); err != nil {
			return fmt.Errorf("invalid subject: %w", err)
		}
	}

	// If either is nil, they match (undefined field matches anything).
	if a == nil || b == nil {
		return nil
	}

	if a.Format != b.Format {
		return errors.New("subject formats do not match")
	}

	// For simple subjects, two subjects match if they are exactly identical.
	if a.Format != goidc.SSFSubjectFormatComplex && b.Format != goidc.SSFSubjectFormatComplex && !reflect.DeepEqual(*a, *b) {
		return errors.New("subjects do not match")
	}

	// For complex subjects, two subjects match if, for all fields in the complex subject
	// (i.e. user, group, device, etc.), at least one of the following statements is true:
	// - Subject 1's field is not defined (nil).
	// - Subject 2's field is not defined (nil).
	// - Subject 1's field is identical to Subject 2's field.
	if err := compareSubjects(ctx, a.User, b.User); err != nil {
		return fmt.Errorf("user subjects do not match: %w", err)
	}
	if err := compareSubjects(ctx, a.Tenant, b.Tenant); err != nil {
		return fmt.Errorf("tenant subjects do not match: %w", err)
	}
	if err := compareSubjects(ctx, a.Device, b.Device); err != nil {
		return fmt.Errorf("device subjects do not match: %w", err)
	}
	if err := compareSubjects(ctx, a.Session, b.Session); err != nil {
		return fmt.Errorf("session subjects do not match: %w", err)
	}
	if err := compareSubjects(ctx, a.OrganizationalUnit, b.OrganizationalUnit); err != nil {
		return fmt.Errorf("org_unit subjects do not match: %w", err)
	}
	if err := compareSubjects(ctx, a.Application, b.Application); err != nil {
		return fmt.Errorf("application subjects do not match: %w", err)
	}
	if err := compareSubjects(ctx, a.Group, b.Group); err != nil {
		return fmt.Errorf("group subjects do not match: %w", err)
	}

	// For each key present in both maps, values must be identical.
	for key, aVal := range a.AdditionalMembers {
		if bVal, exists := b.AdditionalMembers[key]; exists {
			if !reflect.DeepEqual(aVal, bVal) {
				return fmt.Errorf("additional member %q subjects do not match", key)
			}
		}
	}

	return nil
}

func validateSubject(ctx oidc.Context, sub goidc.SSFSubject) error { //nolint:unparam
	allowed, ok := map[goidc.SSFSubjectFormat]struct {
		id, email, phone, uri, iss, sub, url, jti, assertionID, issuer bool
		ipAddresses, identifiers                                       bool
		user, tenant, device, session, orgUnit, application, group     bool
		additionalProperties                                           bool
	}{
		goidc.SSFSubjectFormatOpaque:            {id: true},
		goidc.SSFSubjectFormatEmail:             {email: true},
		goidc.SSFSubjectFormatPhoneNumber:       {phone: true},
		goidc.SSFSubjectFormatAccount:           {uri: true},
		goidc.SSFSubjectFormatURI:               {uri: true},
		goidc.SSFSubjectFormatIssuerSubject:     {iss: true, sub: true},
		goidc.SSFSubjectDecentralizedIdentifier: {url: true},
		goidc.SSFSubjectJWTID:                   {jti: true, iss: true},
		goidc.SSFSubjectSAMLAssertionID:         {assertionID: true, issuer: true},
		goidc.SSFSubjectIPAddresses:             {ipAddresses: true},
		goidc.SSFSubjectFormatAliases:           {identifiers: true},
		goidc.SSFSubjectFormatComplex:           {user: true, tenant: true, device: true, session: true, orgUnit: true, application: true, group: true, additionalProperties: true},
	}[sub.Format]
	if !ok {
		return fmt.Errorf("subject format %q is not supported", sub.Format)
	}

	// Check disallowed fields are empty.
	if !allowed.id && sub.ID != "" {
		return fmt.Errorf("id is not allowed for %s subject format", sub.Format)
	}
	if !allowed.email && sub.Email != "" {
		return fmt.Errorf("email is not allowed for %s subject format", sub.Format)
	}
	if !allowed.phone && sub.Phone != "" {
		return fmt.Errorf("phone_number is not allowed for %s subject format", sub.Format)
	}
	if !allowed.uri && sub.URI != "" {
		return fmt.Errorf("uri is not allowed for %s subject format", sub.Format)
	}
	if !allowed.iss && sub.Iss != "" {
		return fmt.Errorf("iss is not allowed for %s subject format", sub.Format)
	}
	if !allowed.sub && sub.Sub != "" {
		return fmt.Errorf("sub is not allowed for %s subject format", sub.Format)
	}
	if !allowed.url && sub.URL != "" {
		return fmt.Errorf("url is not allowed for %s subject format", sub.Format)
	}
	if !allowed.jti && sub.JTI != "" {
		return fmt.Errorf("jti is not allowed for %s subject format", sub.Format)
	}
	if !allowed.assertionID && sub.AssertionID != "" {
		return fmt.Errorf("assertion_id is not allowed for %s subject format", sub.Format)
	}
	if !allowed.issuer && sub.Issuer != "" {
		return fmt.Errorf("issuer is not allowed for %s subject format", sub.Format)
	}
	if !allowed.ipAddresses && sub.IPAddresses != nil {
		return fmt.Errorf("ip-addresses is not allowed for %s subject format", sub.Format)
	}
	if !allowed.identifiers && sub.Identifiers != nil {
		return fmt.Errorf("identifiers is not allowed for %s subject format", sub.Format)
	}
	if !allowed.user && sub.User != nil {
		return fmt.Errorf("user is not allowed for %s subject format", sub.Format)
	}
	if !allowed.tenant && sub.Tenant != nil {
		return fmt.Errorf("tenant is not allowed for %s subject format", sub.Format)
	}
	if !allowed.device && sub.Device != nil {
		return fmt.Errorf("device is not allowed for %s subject format", sub.Format)
	}
	if !allowed.session && sub.Session != nil {
		return fmt.Errorf("session is not allowed for %s subject format", sub.Format)
	}
	if !allowed.orgUnit && sub.OrganizationalUnit != nil {
		return fmt.Errorf("org_unit is not allowed for %s subject format", sub.Format)
	}
	if !allowed.application && sub.Application != nil {
		return fmt.Errorf("application is not allowed for %s subject format", sub.Format)
	}
	if !allowed.group && sub.Group != nil {
		return fmt.Errorf("group is not allowed for %s subject format", sub.Format)
	}
	if !allowed.additionalProperties && sub.AdditionalMembers != nil {
		return fmt.Errorf("additional properties are not allowed for %s subject format", sub.Format)
	}

	// Format-specific required field validation.
	switch sub.Format {
	case goidc.SSFSubjectFormatOpaque:
		if sub.ID == "" {
			return errors.New("id is required for opaque subject format")
		}
	case goidc.SSFSubjectFormatEmail:
		if sub.Email == "" {
			return errors.New("email is required for email subject format")
		}
	case goidc.SSFSubjectFormatPhoneNumber:
		if sub.Phone == "" {
			return errors.New("phone_number is required for phone_number subject format")
		}
	case goidc.SSFSubjectFormatAccount, goidc.SSFSubjectFormatURI:
		if sub.URI == "" {
			return fmt.Errorf("uri is required for %s subject format", sub.Format)
		}
	case goidc.SSFSubjectFormatIssuerSubject:
		if sub.Iss == "" {
			return errors.New("iss is required for iss_sub subject format")
		}
		if sub.Sub == "" {
			return errors.New("sub is required for iss_sub subject format")
		}
	case goidc.SSFSubjectDecentralizedIdentifier:
		if sub.URL == "" {
			return errors.New("url is required for did subject format")
		}
	case goidc.SSFSubjectJWTID:
		if sub.JTI == "" {
			return errors.New("jti is required for jwt_id subject format")
		}
		if sub.Iss == "" {
			return errors.New("iss is required for jwt_id subject format")
		}
	case goidc.SSFSubjectSAMLAssertionID:
		if sub.AssertionID == "" {
			return errors.New("assertion_id is required for saml_assertion_id subject format")
		}
		if sub.Issuer == "" {
			return errors.New("issuer is required for saml_assertion_id subject format")
		}
	case goidc.SSFSubjectIPAddresses:
		if len(sub.IPAddresses) == 0 {
			return errors.New("ip-addresses is required for ip-addresses subject format")
		}
		for _, ip := range sub.IPAddresses {
			if _, err := netip.ParseAddr(ip); err != nil {
				return fmt.Errorf("invalid ip-addresses value %q", ip)
			}
		}
	case goidc.SSFSubjectFormatAliases:
		if len(sub.Identifiers) == 0 {
			return errors.New("identifiers is required for aliases subject format")
		}
		for _, member := range sub.Identifiers {
			// [RFC 9493 §3.2.8] A member of an alias must not be an alias.
			if member.Format == goidc.SSFSubjectFormatAliases {
				return errors.New("aliases cannot contain aliases")
			}
			if member.Format == goidc.SSFSubjectFormatComplex {
				return errors.New("aliases cannot contain complex subjects")
			}
			if err := validateSubject(ctx, member); err != nil {
				return fmt.Errorf("invalid alias member: %w", err)
			}
		}
	case goidc.SSFSubjectFormatComplex:
		var members []goidc.SSFSubject
		if sub.User != nil {
			members = append(members, *sub.User)
		}
		if sub.Tenant != nil {
			members = append(members, *sub.Tenant)
		}
		if sub.Device != nil {
			members = append(members, *sub.Device)
		}
		if sub.Session != nil {
			members = append(members, *sub.Session)
		}
		if sub.OrganizationalUnit != nil {
			members = append(members, *sub.OrganizationalUnit)
		}
		if sub.Application != nil {
			members = append(members, *sub.Application)
		}
		if sub.Group != nil {
			members = append(members, *sub.Group)
		}
		for _, m := range sub.AdditionalMembers {
			members = append(members, m)
		}

		// [SSF 1.0 §3.3] A complex subject must contain at least one field.
		if len(members) == 0 {
			return errors.New("at least one member is required for complex subject format")
		}

		for _, m := range members {
			// [SSF 1.0 §3.3] Complex subject members must be simple subject members.
			if m.Format == goidc.SSFSubjectFormatComplex {
				return errors.New("complex subject members cannot contain complex subjects")
			}
			if err := validateSubject(ctx, m); err != nil {
				return fmt.Errorf("invalid complex subject member: %w", err)
			}
		}
	}

	return nil
}
