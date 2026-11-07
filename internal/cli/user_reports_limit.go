package cli

// 'user reports-limit <username> [max-size|max-count] [<value>|clear]'
// (docs/plans/0.2.26-plan.md D326): a user's own limits of the stored reports,
// the largest report in bytes and the most reports the user keeps. They are
// fields of the user record (reports_max_size, reports_max_count), written only
// when set, and win over the server's settings ('tacctl config reports') for
// that user; 0 is no cap, and 'clear' returns the user to the server's value.
// The verb is the superuser's (no tier row names it); 'user show' lists the
// limits a user has.

import (
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/store"
)

const userReportsLimitUsage = "Usage: tacctl user reports-limit <username> [max-size|max-count [<value>|clear] | clear]"

// userReportsLimit: with the name alone it shows both limits; 'max-size' or
// 'max-count' alone shows that one; with a value it sets it and 'clear'
// removes it; 'clear' after the name removes both.
func (inv *invocation) userReportsLimit(args []string) error {
	username, which := arg(args, 0), arg(args, 1)
	if username == "" || len(args) > 3 || (which == names.ClearWord && len(args) > 2) {
		return inv.usageErr(userReportsLimitUsage)
	}
	switch which {
	case "", "max-size", "max-count", names.ClearWord:
	default:
		return inv.usageErr("Unknown argument: '"+which+"'", userReportsLimitUsage)
	}
	if err := inv.requireStore(); err != nil {
		return err
	}
	if err := names.ValidateExistingUsername(username); err != nil {
		return err
	}
	u, ok, err := inv.userInfo(username)
	if err != nil {
		return err
	}
	if !ok {
		return inv.usageErr("User '" + username + "' does not exist.")
	}
	if len(args) < 3 && which != names.ClearWord {
		inv.userReportsLimitShow(username, u, which)
		return nil
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	if usr := m.User(username); usr != nil && usr.AccountingSink {
		return inv.usageErr("User '" + username + "' is the accounting sink and takes no limit of the stored reports.")
	}
	if which == names.ClearWord {
		return inv.userReportsLimitClear(username, u, []string{"max-size", "max-count"})
	}
	if args[2] == names.ClearWord {
		return inv.userReportsLimitClear(username, u, []string{which})
	}
	return inv.userReportsLimitSet(username, u, which, args[2])
}

// userReportsLimitShow prints the limits of the user: the own one where there
// is one, else the server's setting that stands for the user.
func (inv *invocation) userReportsLimitShow(username string, u userInfo, which string) {
	size, count := inv.globalReportLimits()
	inv.echo("")
	inv.echo("  Report limits of " + username)
	if which != "max-count" {
		if u.reportsMaxSize != nil {
			inv.echo("  max-size:  " + names.FormatReportSize(*u.reportsMaxSize) + "   (own limit; the server's setting is " + names.FormatReportSize(size) + ")")
		} else {
			inv.echo("  max-size:  " + names.FormatReportSize(size) + "   (the server's setting)")
		}
	}
	if which != "max-size" {
		if u.reportsMaxCount != nil {
			inv.echo("  max-count: " + names.FormatReportCount(*u.reportsMaxCount) + "   (own limit; the server's setting is " + names.FormatReportCount(count) + ")")
		} else {
			inv.echo("  max-count: " + names.FormatReportCount(count) + "   (the server's setting)")
		}
	}
	inv.echo("")
}

// userReportsLimitSet sets one limit of the user; the value is checked before
// anything is written, and the same value again changes nothing.
func (inv *invocation) userReportsLimitSet(username string, u userInfo, which, value string) error {
	var field, text string
	switch which {
	case "max-size":
		n, err := names.ParseReportSize(value)
		if err != nil {
			return inv.usageErr(err.Error(), userReportsLimitUsage)
		}
		if u.reportsMaxSize != nil && *u.reportsMaxSize == n {
			inv.app.Out.Info("User '" + username + "' has that max-size already.")
			return nil
		}
		field, text = store.ReportsMaxSizeKey, strconv.FormatInt(n, 10)
	default:
		n, err := names.ParseReportCount(value)
		if err != nil {
			return inv.usageErr(err.Error(), userReportsLimitUsage)
		}
		if u.reportsMaxCount != nil && *u.reportsMaxCount == n {
			inv.app.Out.Info("User '" + username + "' has that max-count already.")
			return nil
		}
		field, text = store.ReportsMaxCountKey, strconv.Itoa(n)
	}
	if err := inv.storeApply(func(s *store.Store) error { return s.UserSet(username, field+"="+text) }); err != nil {
		return err
	}
	inv.detail("user reports-limit", kvp("name", username), kvp("key", which), kvp("op", "set"), kvp("value", text))
	var said string
	if which == "max-size" {
		n, _ := strconv.ParseInt(text, 10, 64)
		said = names.FormatReportSize(n)
	} else {
		n, _ := strconv.Atoi(text)
		said = names.FormatReportCount(n)
	}
	inv.app.Out.Info("The " + which + " of '" + username + "' set to " + said + ".")
	return nil
}

// userReportsLimitClear removes the named limits the user has; one the user
// does not have is left as it is, and nothing is written when none is there.
func (inv *invocation) userReportsLimitClear(username string, u userInfo, which []string) error {
	var fields, cleared []string
	for _, w := range which {
		switch {
		case w == "max-size" && u.reportsMaxSize != nil:
			fields = append(fields, store.ReportsMaxSizeKey+"=null")
			cleared = append(cleared, w)
		case w == "max-count" && u.reportsMaxCount != nil:
			fields = append(fields, store.ReportsMaxCountKey+"=null")
			cleared = append(cleared, w)
		}
	}
	if len(fields) == 0 {
		inv.app.Out.Info("User '" + username + "' has no own " + strings.Join(which, " or ") + "; nothing to clear.")
		return nil
	}
	if err := inv.storeApply(func(s *store.Store) error { return s.UserSet(username, fields...) }); err != nil {
		return err
	}
	inv.detail("user reports-limit", kvp("name", username), kvp("key", strings.Join(cleared, ",")), kvp("op", "clear"))
	inv.app.Out.Info("The own " + strings.Join(cleared, " and ") + " of '" + username + "' cleared; the server's setting applies.")
	return nil
}
