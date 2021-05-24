use std::{convert::TryInto, fmt::Display};

use async_trait::async_trait;
use kube::Api;
use kube::Client;
use kube::{
    api::{DynamicObject, ResourceExt},
    client::discovery::Discovery,
};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GatekeeperError {
    #[error("kube api error")]
    Kube(#[from] kube::Error),
    #[error("unknown gatekeeper error")]
    Unknown,
    #[error("conversion error")]
    FailedConversion,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConstraintTemplate {
    #[serde(default)]
    pub name: String,
    #[serde(rename = "spec")]
    pub spec: ConstraintTemplateSpec,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ConstraintTemplateSpec {
    pub targets: Vec<TemplateTarget>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TemplateTarget {
    pub target: String,
    pub rego: String,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct Constraint {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub name: String,
    #[serde(rename = "spec")]
    pub spec: ConstraintSpec,
    #[serde(rename = "status")]
    pub status: ConstraintStatus,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum EnforcementAction {
    #[serde(rename = "dryrun")]
    DryRun,
    #[serde(rename = "warn")]
    Warn,
    #[serde(rename = "deny")]
    Deny,
}

impl Default for EnforcementAction {
    fn default() -> Self {
        EnforcementAction::Deny
    }
}

impl Display for EnforcementAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ConstraintSpec {
    #[serde(rename = "enforcementAction", default)]
    pub enforcement_action: EnforcementAction,
    #[serde(rename = "match")]
    pub match_spec: Option<MatchSpec>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub enum MatchScope {
    #[serde(rename = "*")]
    Everything,
    #[serde(rename = "Cluster")]
    Cluster,
    #[serde(rename = "Namespaced")]
    Namespaced,
}

impl Default for MatchScope {
    fn default() -> Self {
        MatchScope::Everything
    }
}
impl Display for MatchScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MatchSpec {
    #[serde(default)]
    pub scope: MatchScope,
    #[serde(default)]
    pub namespaces: Option<Vec<String>>,
    #[serde(rename = "excludedNamespaces", default)]
    pub excluded_namespaces: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ConstraintStatus {
    #[serde(rename = "auditTimestamp")]
    pub audit_timestamp: String,
    #[serde(rename = "totalViolations")]
    pub total_violations: i16,
    pub violations: Vec<Violation>,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct Violation {
    #[serde(rename = "enforcementAction")]
    pub enforcement_action: EnforcementAction,
    pub kind: String,
    pub message: String,
    pub name: String,
    #[serde(default = "default_namespace")]
    pub namespace: String,
}

fn default_namespace() -> String {
    "".to_string()
}

impl TryInto<ConstraintTemplate> for DynamicObject {
    type Error = GatekeeperError;

    fn try_into(self) -> Result<ConstraintTemplate, Self::Error> {
        let name = self.name();

        let mut constraint_template: ConstraintTemplate = serde_json::from_value(self.data)
            .map_err(|t| {
                info!("{:?}", t);
                GatekeeperError::FailedConversion
            })?;

        constraint_template.name = name;
        Ok(constraint_template)
    }
}

impl TryInto<Constraint> for DynamicObject {
    type Error = GatekeeperError;

    fn try_into(self) -> Result<Constraint, Self::Error> {
        let name = self.name();
        let kind = self.types.ok_or(GatekeeperError::FailedConversion)?.kind;

        let mut constraint: Constraint = serde_json::from_value(self.data).map_err(|t| {
            info!("{:?}", t);
            GatekeeperError::FailedConversion
        })?;
        constraint.name = name;
        constraint.kind = kind;
        Ok(constraint)
    }
}

#[async_trait]
pub trait GatekeeperClient {
    async fn get_constraint_templates(&self) -> Result<Vec<ConstraintTemplate>, GatekeeperError>;
    async fn get_constraints(&self) -> Result<Vec<Constraint>, GatekeeperError>;
}

pub struct KubeGatekeeperClient {
    client: Client,
}

impl KubeGatekeeperClient {
    pub fn new(client: Client) -> KubeGatekeeperClient {
        KubeGatekeeperClient { client }
    }
    async fn get_items(&self, group: &str) -> Result<Vec<DynamicObject>, GatekeeperError> {
        let discovery = Discovery::new(&self.client).await?;
        let group = discovery.group(group);
        let group = if group.is_some() {
            group.unwrap()
        } else {
            return Ok(Vec::new());
        };
        let mut items = Vec::new();

        let ver = group.preferred_version_or_guess();
        for gvk in group.resources_by_version(ver) {
            let api: Api<DynamicObject> = Api::all_with(self.client.clone(), &gvk.0);
            let mut list = match api.list(&Default::default()).await {
                Ok(l) => l,
                Err(e) => {
                    warn!("Failed to list: {:#}", e);
                    continue;
                }
            };
            items.append(&mut list.items)
        }
        Ok(items)
    }
}

#[async_trait]
impl GatekeeperClient for KubeGatekeeperClient {
    async fn get_constraint_templates(&self) -> Result<Vec<ConstraintTemplate>, GatekeeperError> {
        let items = self.get_items("templates.gatekeeper.sh").await?;
        let mut vector: Vec<ConstraintTemplate> = Vec::new();
        for item in items {
            let item = item.try_into()?;
            vector.push(item)
        }
        Ok(vector)
    }

    async fn get_constraints(&self) -> Result<Vec<Constraint>, GatekeeperError> {
        let items = self.get_items("constraints.gatekeeper.sh").await?;
        let mut vector: Vec<Constraint> = Vec::new();
        for item in items {
            let item = item.try_into()?;
            vector.push(item)
        }
        Ok(vector)
    }
}
