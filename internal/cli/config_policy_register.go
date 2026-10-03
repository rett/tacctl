// registerConfigVerb (config.go) replaces the delegated stubs of
// 'config allow|deny|mgmt-acl' with the native families of
// config_policy.go.
package cli

func init() {
	registerConfigVerb("allow", configPolicyFamilySpecs["allow"], configAllowCmd)
	registerConfigVerb("deny", configPolicyFamilySpecs["deny"], configDenyCmd)
	registerConfigVerb("mgmt-acl", configPolicyFamilySpecs["mgmt-acl"], configMgmtACLCmd)
}
