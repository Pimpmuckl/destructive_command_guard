//! Railway Platform pack - protections for destructive Railway CLI and API operations.
//!
//! Railway projects commonly hold production databases, attached volumes,
//! environment variables, and deployments. This pack blocks operations that can
//! delete or detach those resources through either the Railway CLI or the public
//! GraphQL API.

use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern};
use crate::{destructive_pattern, safe_pattern};

const PROJECT_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "railway status",
        "Confirm the currently linked project and environment before any project change",
    ),
    PatternSuggestion::new(
        "railway list",
        "List projects to verify the target instead of deleting it",
    ),
];

const ENVIRONMENT_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "railway environment list",
        "List environments and verify that production is not the target",
    ),
    PatternSuggestion::new(
        "railway status",
        "Confirm the active project and environment before making changes",
    ),
];

const SERVICE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "railway service list",
        "List services before deleting or changing one",
    ),
    PatternSuggestion::new(
        "railway logs",
        "Inspect the service state without removing it",
    ),
];

const VOLUME_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "railway volume list",
        "List volumes and identify any database storage before changing it",
    ),
    PatternSuggestion::new(
        "railway status",
        "Confirm the active project and environment before touching volumes",
    ),
];

const VARIABLE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "railway variable list",
        "Review variables before deleting or overwriting them",
    ),
    PatternSuggestion::new(
        "railway variable list --json",
        "Capture the current values in a reviewable format before changing secrets",
    ),
];

const DEPLOYMENT_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "railway status",
        "Confirm the target service and environment before removing deployments",
    ),
    PatternSuggestion::new(
        "railway logs",
        "Inspect deployment state without stopping or removing it",
    ),
];

/// Create the Railway Platform pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "platform.railway".to_string(),
        name: "Railway Platform",
        description: "Protects against destructive Railway CLI and Public API operations that can delete projects, environments, services, volumes, variables, or deployments.",
        keywords: &[
            "railway",
            "backboard.railway.app",
            "backboard.railway.com",
            "railway.app/graphql",
            "railway.com/graphql",
            "projectDelete",
            "projectScheduleDelete",
            "environmentDelete",
            "serviceDelete",
            "volumeDelete",
            "volumeInstanceDelete",
            "volumeInstanceUpdate",
            "variableDelete",
            "variableCollectionUpsert",
            "deploymentRemove",
            "deploymentStop",
        ],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!(
            "railway-status",
            r"railway(?:\s+--?\S+(?:\s+\S+)?)*\s+status(?:\s|$)"
        ),
        safe_pattern!(
            "railway-project-list",
            r"railway(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:list|ls)(?:\s|$)"
        ),
        safe_pattern!(
            "railway-project-subcommand-list",
            r"railway(?:\s+--?\S+(?:\s+\S+)?)*\s+project\s+(?:list|ls)(?:\s|$)"
        ),
        safe_pattern!(
            "railway-whoami",
            r"railway(?:\s+--?\S+(?:\s+\S+)?)*\s+whoami(?:\s|$)"
        ),
        safe_pattern!(
            "railway-logs",
            r"railway(?:\s+--?\S+(?:\s+\S+)?)*\s+logs(?:\s|$)"
        ),
        safe_pattern!(
            "railway-service-list",
            r"railway(?:\s+--?\S+(?:\s+\S+)?)*\s+service\s+(?:list|ls)(?:\s|$)"
        ),
        safe_pattern!(
            "railway-environment-list",
            r"railway(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:environment|env)\s+(?:list|ls)(?:\s|$)"
        ),
        safe_pattern!(
            "railway-volume-list",
            r"railway(?:\s+--?\S+(?:\s+\S+)?)*\s+volume\s+(?:list|ls)(?:\s|$)"
        ),
        safe_pattern!(
            "railway-variable-list",
            r"railway(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:variable|variables|vars|var)\s+(?:list|ls)(?:\s|$)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "railway-project-delete",
            r"railway(?:\s+--?\S+(?:\s+\S+)?)*\s+delete(?:\s|$)",
            "railway delete schedules deletion of the entire Railway project.",
            Critical,
            "Deleting a Railway project can remove every service, database, volume, variable, and deployment attached to it.",
            PROJECT_SUGGESTIONS
        ),
        destructive_pattern!(
            "railway-project-subcommand-delete",
            r"railway(?:\s+--?\S+(?:\s+\S+)?)*\s+project\s+(?:delete|remove|rm)(?:\s|$)",
            "railway project delete schedules deletion of the entire Railway project.",
            Critical,
            "Deleting a Railway project can remove every service, database, volume, variable, and deployment attached to it.",
            PROJECT_SUGGESTIONS
        ),
        destructive_pattern!(
            "railway-environment-delete",
            r"railway(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:environment|env)\s+(?:delete|remove|rm)(?:\s|$)",
            "railway environment delete removes a Railway environment and its resources.",
            Critical,
            "Deleting an environment can remove production services, database instances, volumes, and variables in that environment.",
            ENVIRONMENT_SUGGESTIONS
        ),
        destructive_pattern!(
            "railway-service-delete",
            r"railway(?:\s+--?\S+(?:\s+\S+)?)*\s+service\s+(?:delete|remove|rm)(?:\s|$)",
            "railway service delete permanently deletes a Railway service.",
            Critical,
            "Deleting a service can remove the production app or managed database service and its deployment history.",
            SERVICE_SUGGESTIONS
        ),
        destructive_pattern!(
            "railway-volume-delete",
            r"railway(?:\s+--?\S+(?:\s+\S+)?)*\s+volume\s+(?:delete|remove|rm)(?:\s|$)",
            "railway volume delete removes persistent Railway storage.",
            Critical,
            "Deleting a Railway volume can destroy persistent database storage and is catastrophic when the volume backs production data.",
            VOLUME_SUGGESTIONS
        ),
        destructive_pattern!(
            "railway-volume-detach",
            r"railway(?:\s+--?\S+(?:\s+\S+)?)*\s+volume\s+detach(?:\s|$)",
            "railway volume detach disconnects persistent storage from a service.",
            High,
            "Detaching a volume can take a production database or stateful service offline even when the bytes are not immediately deleted.",
            VOLUME_SUGGESTIONS
        ),
        destructive_pattern!(
            "railway-variable-delete",
            r"railway(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:variable|variables|vars|var)\s+(?:delete|remove|rm)(?:\s|$)",
            "railway variable delete removes Railway environment variables.",
            High,
            "Deleting environment variables can break production deploys, database connections, credentials, and service-to-service links.",
            VARIABLE_SUGGESTIONS
        ),
        destructive_pattern!(
            "railway-database-variable-set",
            r"railway(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:variable|variables|vars|var)\s+(?:set|upsert)(?:\s|.)*(?:DATABASE_URL|DATABASE_PRIVATE_URL|RAILWAY_DATABASE_URL|PGHOST|POSTGRES_HOST|MYSQL_URL|REDIS_URL|MONGO_URL|MONGODB_URI)(?:\s|=|$)",
            "railway variable set is changing a database connection variable.",
            High,
            "Overwriting database connection variables can redirect production traffic or disconnect an app from its production database.",
            VARIABLE_SUGGESTIONS
        ),
        destructive_pattern!(
            "railway-database-variable-legacy-set",
            r"railway(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:variable|variables|vars|var)(?:\s+--?\S+(?:\s+\S+)?)*(?:\s+--set(?:=|\s+)|\s+--set-from-stdin(?:=|\s+))(?:DATABASE_URL|DATABASE_PRIVATE_URL|RAILWAY_DATABASE_URL|PGHOST|POSTGRES_HOST|MYSQL_URL|REDIS_URL|MONGO_URL|MONGODB_URI)(?:\s|=|$)",
            "railway variable legacy flags are changing a database connection variable.",
            High,
            "Legacy Railway variable flags can still overwrite database connection variables and break production database access.",
            VARIABLE_SUGGESTIONS
        ),
        destructive_pattern!(
            "railway-deployment-remove",
            r"railway(?:\s+--?\S+(?:\s+\S+)?)*\s+down(?:\s|$)",
            "railway down removes the latest successful deployment.",
            High,
            "Removing a deployment can interrupt production service availability.",
            DEPLOYMENT_SUGGESTIONS
        ),
        destructive_pattern!(
            "railway-api-project-delete",
            r"(?i)(?:curl|graphql|backboard\.railway\.(?:app|com)|railway\.(?:app|com)/graphql).*(?:projectDelete|projectScheduleDelete)|(?:projectDelete|projectScheduleDelete).*(?:curl|graphql|backboard\.railway\.(?:app|com)|railway\.(?:app|com)/graphql)",
            "Railway Public API project deletion mutation detected.",
            Critical,
            "Railway GraphQL project deletion mutations can remove an entire project and all attached production resources.",
            PROJECT_SUGGESTIONS
        ),
        destructive_pattern!(
            "railway-api-environment-delete",
            r"(?i)(?:curl|graphql|backboard\.railway\.(?:app|com)|railway\.(?:app|com)/graphql).*environmentDelete|environmentDelete.*(?:curl|graphql|backboard\.railway\.(?:app|com)|railway\.(?:app|com)/graphql)",
            "Railway Public API environment deletion mutation detected.",
            Critical,
            "Railway GraphQL environment deletion mutations can remove production services, databases, volumes, and variables.",
            ENVIRONMENT_SUGGESTIONS
        ),
        destructive_pattern!(
            "railway-api-service-delete",
            r"(?i)(?:curl|graphql|backboard\.railway\.(?:app|com)|railway\.(?:app|com)/graphql).*serviceDelete|serviceDelete.*(?:curl|graphql|backboard\.railway\.(?:app|com)|railway\.(?:app|com)/graphql)",
            "Railway Public API service deletion mutation detected.",
            Critical,
            "Railway GraphQL service deletion mutations can remove a production app or managed database service.",
            SERVICE_SUGGESTIONS
        ),
        destructive_pattern!(
            "railway-api-volume-delete",
            r"(?i)(?:curl|graphql|backboard\.railway\.(?:app|com)|railway\.(?:app|com)/graphql).*(?:volumeDelete|volumeInstanceDelete)|(?:volumeDelete|volumeInstanceDelete).*(?:curl|graphql|backboard\.railway\.(?:app|com)|railway\.(?:app|com)/graphql)",
            "Railway Public API volume deletion mutation detected.",
            Critical,
            "Railway GraphQL volume deletion mutations can destroy persistent database storage.",
            VOLUME_SUGGESTIONS
        ),
        destructive_pattern!(
            "railway-api-volume-detach",
            r"(?i)(?:curl|graphql|backboard\.railway\.(?:app|com)|railway\.(?:app|com)/graphql).*volumeInstanceUpdate.*serviceId\s*:\s*null|volumeInstanceUpdate.*serviceId\s*:\s*null.*(?:curl|graphql|backboard\.railway\.(?:app|com)|railway\.(?:app|com)/graphql)",
            "Railway Public API volume detach mutation detected.",
            High,
            "Railway GraphQL volumeInstanceUpdate with serviceId null detaches persistent storage from its service.",
            VOLUME_SUGGESTIONS
        ),
        destructive_pattern!(
            "railway-api-variable-delete",
            r"(?i)(?:curl|graphql|backboard\.railway\.(?:app|com)|railway\.(?:app|com)/graphql).*variableDelete|variableDelete.*(?:curl|graphql|backboard\.railway\.(?:app|com)|railway\.(?:app|com)/graphql)",
            "Railway Public API variable deletion mutation detected.",
            High,
            "Railway GraphQL variable deletion mutations can remove credentials or database connection variables from production environments.",
            VARIABLE_SUGGESTIONS
        ),
        destructive_pattern!(
            "railway-api-database-variable-upsert",
            r"(?i)(?:curl|graphql|backboard\.railway\.(?:app|com)|railway\.(?:app|com)/graphql).*variableCollectionUpsert.*(?:DATABASE_URL|DATABASE_PRIVATE_URL|RAILWAY_DATABASE_URL|PGHOST|POSTGRES_HOST|MYSQL_URL|REDIS_URL|MONGO_URL|MONGODB_URI)|variableCollectionUpsert.*(?:DATABASE_URL|DATABASE_PRIVATE_URL|RAILWAY_DATABASE_URL|PGHOST|POSTGRES_HOST|MYSQL_URL|REDIS_URL|MONGO_URL|MONGODB_URI).*(?:curl|graphql|backboard\.railway\.(?:app|com)|railway\.(?:app|com)/graphql)",
            "Railway Public API upsert is changing a database connection variable.",
            High,
            "Bulk-upserting Railway variables that include database connection keys can redirect or sever production database access.",
            VARIABLE_SUGGESTIONS
        ),
        destructive_pattern!(
            "railway-api-deployment-remove",
            r"(?i)(?:curl|graphql|backboard\.railway\.(?:app|com)|railway\.(?:app|com)/graphql).*(?:deploymentRemove|deploymentStop)|(?:deploymentRemove|deploymentStop).*(?:curl|graphql|backboard\.railway\.(?:app|com)|railway\.(?:app|com)/graphql)",
            "Railway Public API deployment removal or stop mutation detected.",
            High,
            "Railway GraphQL deployment removal and stop mutations can interrupt production availability.",
            DEPLOYMENT_SUGGESTIONS
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn test_pack_creation() {
        let pack = create_pack();
        assert_eq!(pack.id, "platform.railway");
        assert_eq!(pack.name, "Railway Platform");
        assert!(pack.keywords.contains(&"railway"));
        assert!(pack.keywords.contains(&"projectScheduleDelete"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_read_only_cli_commands() {
        let pack = create_pack();
        assert_allows(&pack, "railway status");
        assert_allows(&pack, "railway list");
        assert_allows(&pack, "railway project list");
        assert_allows(&pack, "railway whoami");
        assert_allows(&pack, "railway logs --service web");
        assert_allows(&pack, "railway service list --json");
        assert_allows(&pack, "railway environment list");
        assert_allows(&pack, "railway env list");
        assert_allows(&pack, "railway volume list");
        assert_allows(&pack, "railway variable list");
        assert_allows(&pack, "railway vars list");
    }

    #[test]
    fn blocks_destructive_cli_commands() {
        let pack = create_pack();
        let checks = [
            ("railway delete --yes", "railway-project-delete"),
            (
                "railway project remove --project prod --yes",
                "railway-project-subcommand-delete",
            ),
            (
                "railway environment delete production --yes",
                "railway-environment-delete",
            ),
            (
                "railway env rm production --yes",
                "railway-environment-delete",
            ),
            (
                "railway service delete --service postgres --yes",
                "railway-service-delete",
            ),
            (
                "railway service rm --service api --yes",
                "railway-service-delete",
            ),
            (
                "railway volume delete --volume data --yes",
                "railway-volume-delete",
            ),
            (
                "railway volume detach --volume prod-db --yes",
                "railway-volume-detach",
            ),
            (
                "railway variable delete DATABASE_URL",
                "railway-variable-delete",
            ),
            ("railway vars rm DATABASE_URL", "railway-variable-delete"),
            (
                "railway variable set DATABASE_URL=postgres://prod",
                "railway-database-variable-set",
            ),
            (
                "railway variables --set DATABASE_URL=postgres://prod",
                "railway-database-variable-legacy-set",
            ),
            (
                "railway var --set-from-stdin DATABASE_URL",
                "railway-database-variable-legacy-set",
            ),
            ("railway down --yes", "railway-deployment-remove"),
        ];

        for (command, expected_pattern) in checks {
            assert_blocks_with_pattern(&pack, command, expected_pattern);
        }
    }

    #[test]
    fn blocks_destructive_public_api_mutations() {
        let pack = create_pack();
        let checks = [
            (
                r#"curl https://backboard.railway.app/graphql/v2 -d '{"query":"mutation { projectDelete(id:\"p\") }"}'"#,
                "railway-api-project-delete",
            ),
            (
                r#"curl https://backboard.railway.com/graphql/v2 -d '{"query":"mutation { projectScheduleDelete(id:\"p\") }"}'"#,
                "railway-api-project-delete",
            ),
            (
                r#"curl https://backboard.railway.app/graphql/v2 -d '{"query":"mutation { environmentDelete(id:\"e\") }"}'"#,
                "railway-api-environment-delete",
            ),
            (
                r#"curl https://backboard.railway.app/graphql/v2 -d '{"query":"mutation { serviceDelete(id:\"s\", environmentId:\"e\") }"}'"#,
                "railway-api-service-delete",
            ),
            (
                r#"curl https://backboard.railway.app/graphql/v2 -d '{"query":"mutation { volumeDelete(volumeId:\"v\") }"}'"#,
                "railway-api-volume-delete",
            ),
            (
                r#"curl https://backboard.railway.app/graphql/v2 -d '{"query":"mutation { volumeInstanceUpdate(input:{serviceId:null, volumeId:\"v\"}) }"}'"#,
                "railway-api-volume-detach",
            ),
            (
                r#"curl https://backboard.railway.app/graphql/v2 -d '{"query":"mutation { variableDelete(input:{projectId:\"p\", environmentId:\"e\", name:\"DATABASE_URL\"}) }"}'"#,
                "railway-api-variable-delete",
            ),
            (
                r#"curl https://backboard.railway.app/graphql/v2 -d '{"query":"mutation { variableCollectionUpsert(input:{variables:[{name:\"DATABASE_URL\", value:\"postgres://prod\"}]}) }"}'"#,
                "railway-api-database-variable-upsert",
            ),
            (
                r#"curl https://backboard.railway.app/graphql/v2 -d '{"query":"mutation { deploymentRemove(id:\"d\") }"}'"#,
                "railway-api-deployment-remove",
            ),
        ];

        for (command, expected_pattern) in checks {
            assert_blocks_with_pattern(&pack, command, expected_pattern);
        }
    }

    #[test]
    fn allows_safe_api_and_documentation_mentions() {
        let pack = create_pack();
        assert_allows(
            &pack,
            r#"curl https://backboard.railway.app/graphql/v2 -d '{"query":"query { project(id:\"p\") { id name } }"}'"#,
        );
        assert_allows(&pack, "grep projectDelete docs/railway.md");
        assert_allows(&pack, "echo serviceDelete is a mutation name");
        assert_allows(&pack, "railway variable set FEATURE_FLAG=true");
        assert_allows(&pack, "railway variables --set FEATURE_FLAG=true");
    }

    #[test]
    fn safe_cli_segment_does_not_mask_later_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "railway service list && railway volume delete --volume prod-db --yes",
            "railway-volume-delete",
        );
    }

    #[test]
    fn destructive_patterns_have_expected_severities() {
        let pack = create_pack();
        let critical = [
            "railway delete --yes",
            "railway project rm prod --yes",
            "railway environment rm production --yes",
            "railway service remove postgres --yes",
            "railway volume rm prod-db --yes",
        ];
        for command in critical {
            let matched = pack
                .check(command)
                .unwrap_or_else(|| panic!("should block {command}"));
            assert_eq!(matched.severity, Severity::Critical, "command: {command}");
        }

        let matched = pack
            .check("railway variable delete DATABASE_URL")
            .expect("should block variable delete");
        assert_eq!(matched.severity, Severity::High);
    }
}
