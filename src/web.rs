use crate::gatekeeper::{
    Constraint, ConstraintTemplate, GatekeeperClient, GatekeeperError, KubeGatekeeperClient,
};
use actix_web::{get, web, Error, HttpResponse, ResponseError};
use askama::Template;

use log::info;

impl ResponseError for GatekeeperError {}

#[derive(Template)]
#[template(path = "base.html")]
struct BaseTemplate {
    title: String,
    enabled_login: bool,
}

impl BaseTemplate {
    fn new(title: &str) -> BaseTemplate {
        BaseTemplate {
            title: title.into(),
            enabled_login: true,
        }
    }
}
#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    _parent: BaseTemplate,
}

#[derive(Template)]
#[template(path = "config.html")]
struct ConfigTemplate {
    _parent: BaseTemplate,
}

#[derive(Template)]
#[template(path = "constraint.html")]
struct TemplateConstraint {
    _parent: BaseTemplate,
    items: Vec<Constraint>,
}

#[derive(Template)]
#[template(path = "constraint_template.html")]
struct TemplateConstraintTemplate {
    _parent: BaseTemplate,
    items: Vec<ConstraintTemplate>,
}

#[get("/")]
pub async fn index() -> Result<HttpResponse, Error> {
    let t = BaseTemplate::new("Home");
    let s = IndexTemplate { _parent: t }.render().unwrap();

    Ok(HttpResponse::Ok().content_type("text/html").body(s))
}

#[get("/config/")]
pub async fn config() -> Result<HttpResponse, Error> {
    let t = BaseTemplate::new("Config");
    let s = ConfigTemplate { _parent: t }.render().unwrap();

    Ok(HttpResponse::Ok().content_type("text/html").body(s))
}

#[get("/constraint_template/")]
pub async fn constraint_template(
    client: web::Data<KubeGatekeeperClient>,
) -> Result<HttpResponse, Error> {
    let items = client.get_constraint_templates().await?;

    let t = BaseTemplate::new("Constraint Templates");
    let s = TemplateConstraintTemplate { _parent: t, items }
        .render()
        .unwrap();

    Ok(HttpResponse::Ok().content_type("text/html").body(s))
}

#[get("/constraint/")]
pub async fn constraint(client: web::Data<KubeGatekeeperClient>) -> Result<HttpResponse, Error> {
    let items = client.get_constraints().await?;
    info!("constraints: {:#?}", items);

    let t = BaseTemplate::new("Constraints");
    let s = TemplateConstraint { _parent: t, items }.render().unwrap();

    Ok(HttpResponse::Ok().content_type("text/html").body(s))
}
