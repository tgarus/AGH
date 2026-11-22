use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Built-in RBAC roles enforced across asi-api endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub enum Role {
    Admin,
    ReadWriteDelete,
    ReadWrite,
    ReadOnly,
}

/// Atomic permissions mapped strictly from docs/standards/05-rbac-and-security.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    ViewInventoryAndDiffs,
    ExportReports,
    RunOrStopScans,
    EditAnalyticalMetadata,
    AcknowledgeDiffs,
    ManageAssetGroups,
    ManageGroupPolicies,
    ImportData,
    DeleteLocalTargetsAndResults,
    ManageIgnoredTargets,
    ManageCustomSignatures,
    ForceTarpitScan,
    SyncFingerprintHub,
    ManageGlobalPoliciesAndNotifications,
    ManageWorkers,
    ManageUsersAndAudit,
    ManageExternalIntegrations,
}

const READ_ONLY_PERMS: &[Permission] =
    &[Permission::ViewInventoryAndDiffs, Permission::ExportReports];

const READ_WRITE_PERMS: &[Permission] = &[
    Permission::ViewInventoryAndDiffs,
    Permission::ExportReports,
    Permission::RunOrStopScans,
    Permission::EditAnalyticalMetadata,
    Permission::AcknowledgeDiffs,
];

const READ_WRITE_DELETE_PERMS: &[Permission] = &[
    Permission::ViewInventoryAndDiffs,
    Permission::ExportReports,
    Permission::RunOrStopScans,
    Permission::EditAnalyticalMetadata,
    Permission::AcknowledgeDiffs,
    Permission::ManageAssetGroups,
    Permission::ManageGroupPolicies,
    Permission::ImportData,
    Permission::DeleteLocalTargetsAndResults,
    Permission::ManageIgnoredTargets,
    Permission::ManageCustomSignatures,
];

const ADMIN_PERMS: &[Permission] = &[
    Permission::ViewInventoryAndDiffs,
    Permission::ExportReports,
    Permission::RunOrStopScans,
    Permission::EditAnalyticalMetadata,
    Permission::AcknowledgeDiffs,
    Permission::ManageAssetGroups,
    Permission::ManageGroupPolicies,
    Permission::ImportData,
    Permission::DeleteLocalTargetsAndResults,
    Permission::ManageIgnoredTargets,
    Permission::ManageCustomSignatures,
    Permission::ForceTarpitScan,
    Permission::SyncFingerprintHub,
    Permission::ManageGlobalPoliciesAndNotifications,
    Permission::ManageWorkers,
    Permission::ManageUsersAndAudit,
    Permission::ManageExternalIntegrations,
];

impl Role {
    #[must_use]
    pub const fn permissions(self) -> &'static [Permission] {
        match self {
            Self::ReadOnly => READ_ONLY_PERMS,
            Self::ReadWrite => READ_WRITE_PERMS,
            Self::ReadWriteDelete => READ_WRITE_DELETE_PERMS,
            Self::Admin => ADMIN_PERMS,
        }
    }

    #[must_use]
    pub fn has_permission(self, permission: Permission) -> bool {
        self.permissions().contains(&permission)
    }

    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Admin => "Admin",
            Self::ReadWriteDelete => "ReadWriteDelete",
            Self::ReadWrite => "ReadWrite",
            Self::ReadOnly => "ReadOnly",
        }
    }

    #[must_use]
    pub fn from_db_str(raw: &str) -> Option<Self> {
        match raw {
            "Admin" => Some(Self::Admin),
            "ReadWriteDelete" => Some(Self::ReadWriteDelete),
            "ReadWrite" => Some(Self::ReadWrite),
            "ReadOnly" => Some(Self::ReadOnly),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readonly_role_matrix() {
        assert!(Role::ReadOnly.has_permission(Permission::ViewInventoryAndDiffs));
        assert!(Role::ReadOnly.has_permission(Permission::ExportReports));
        assert!(!Role::ReadOnly.has_permission(Permission::RunOrStopScans));
        assert!(!Role::ReadOnly.has_permission(Permission::EditAnalyticalMetadata));
        assert!(!Role::ReadOnly.has_permission(Permission::ManageAssetGroups));
        assert!(!Role::ReadOnly.has_permission(Permission::ForceTarpitScan));
    }

    #[test]
    fn readwrite_role_matrix() {
        assert!(Role::ReadWrite.has_permission(Permission::ViewInventoryAndDiffs));
        assert!(Role::ReadWrite.has_permission(Permission::ExportReports));
        assert!(Role::ReadWrite.has_permission(Permission::RunOrStopScans));
        assert!(Role::ReadWrite.has_permission(Permission::EditAnalyticalMetadata));
        assert!(Role::ReadWrite.has_permission(Permission::AcknowledgeDiffs));
        assert!(!Role::ReadWrite.has_permission(Permission::ManageAssetGroups));
        assert!(!Role::ReadWrite.has_permission(Permission::ManageIgnoredTargets));
        assert!(!Role::ReadWrite.has_permission(Permission::ManageCustomSignatures));
        assert!(!Role::ReadWrite.has_permission(Permission::ForceTarpitScan));
    }

    #[test]
    fn readwritedelete_role_matrix() {
        assert!(Role::ReadWriteDelete.has_permission(Permission::ManageAssetGroups));
        assert!(Role::ReadWriteDelete.has_permission(Permission::ManageGroupPolicies));
        assert!(Role::ReadWriteDelete.has_permission(Permission::ImportData));
        assert!(Role::ReadWriteDelete.has_permission(Permission::DeleteLocalTargetsAndResults));
        assert!(Role::ReadWriteDelete.has_permission(Permission::ManageIgnoredTargets));
        assert!(Role::ReadWriteDelete.has_permission(Permission::ManageCustomSignatures));
        assert!(!Role::ReadWriteDelete.has_permission(Permission::ForceTarpitScan));
        assert!(!Role::ReadWriteDelete.has_permission(Permission::SyncFingerprintHub));
        assert!(!Role::ReadWriteDelete.has_permission(Permission::ManageWorkers));
        assert!(!Role::ReadWriteDelete.has_permission(Permission::ManageUsersAndAudit));
        assert!(!Role::ReadWriteDelete.has_permission(Permission::ManageExternalIntegrations));
    }

    #[test]
    fn admin_role_has_all_permissions() {
        for perm in ADMIN_PERMS {
            assert!(Role::Admin.has_permission(*perm));
        }
        assert_eq!(Role::Admin.permissions().len(), 17);
    }
}
