use axum::{Extension, Json};
use axum::extract::State;
use axum_login::axum_sessions::async_session::base64::CharacterSet;
use tracing::log;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use web_push::{Config, ContentEncoding, SubscriptionInfo, VapidSignatureBuilder, WebPushClient, WebPushMessageBuilder};
use crate::auth::AuthContext;
use sqlx::FromRow;

#[derive(Clone)]
pub struct WebPushState {
    pub vapid_public_key: Option<String>,
    pub(crate) vapid_private_key: Option<String>,
}

impl WebPushState {
    pub fn new(vapid_public_key: Option<String>, vapid_private_key: Option<String>) -> WebPushState {
        // If the keys are not provided, we can't do anything
        if vapid_public_key.is_none() || vapid_private_key.is_none() {
            log::warn!("WebPushState::new(): Vapid keys are not provided. WebPush notifications will not work.");
        }

        WebPushState {
            vapid_public_key,
            vapid_private_key,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebPushJsonResponse {
    pub public_key: String,
}

pub async fn get_vapid_public_key(Extension(state): Extension<WebPushState>) -> String {
    let response = WebPushJsonResponse { public_key: state.vapid_public_key.unwrap() };
    serde_json::to_string(&response).unwrap()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebPushSubscriptionRequest {
    pub endpoint: String,
    pub keys: WebPushUserKeys,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebPushUserKeys {
    pub p256dh: String,
    pub auth: String,
}

pub async fn handle_new_subscription(
    Extension(state): Extension<WebPushState>,
    State(db): State<PgPool>,
    auth: AuthContext,
    Json(subscription): Json<WebPushSubscriptionRequest>,
) -> Result<Json<WebPushSubscriptionRequest>, ()> {
    // If the state is None, we don't have any keys and can't do anything.
    if state.vapid_public_key.is_none() || state.vapid_private_key.is_none() {
        log::warn!("handle_new_subscription: Vapid keys are not provided. WebPush notifications will not work.");
        return Err(());
    }

    // TODO: There is a lot of unwrapping here. We should handle errors properly.
    let passback = subscription.clone();
    let subscription_info = SubscriptionInfo::new(
        subscription.endpoint.clone(),
        subscription.keys.p256dh.clone(),
        subscription.keys.auth.clone(),
    );

    let config = Config::new(
        CharacterSet::Standard,
        false,
    );

    let sig_builder = VapidSignatureBuilder::from_base64(
        &state.vapid_private_key.unwrap(),
        config,
        &subscription_info,
    ).unwrap().build().unwrap();

    let mut builder = WebPushMessageBuilder::new(&subscription_info).unwrap();
    let content = "🐺 Welcome to curiouswolf! You have successfully subscribed to web push notifications.";
    builder.set_payload(ContentEncoding::Aes128Gcm, content.as_bytes());
    builder.set_vapid_signature(sig_builder);

    let client = WebPushClient::new().unwrap();
    match client.send(builder.build().unwrap()).await {
        Ok(_) => {
            log::info!("Successfully sent web push notification");
            let user_id = auth.current_user.unwrap().id;

            // Check if the subscription already exists
            let check_query = r#"
                SELECT * FROM push_subscriptions
                WHERE user_id = $1 AND endpoint = $2 AND p256dh = $3 AND auth = $4
            "#;

            let subscription_exists = sqlx::query_as::<_, PushSubscription>(check_query)
                .bind(user_id)
                .bind(&subscription.endpoint)
                .bind(&subscription.keys.p256dh)
                .bind(&subscription.keys.auth)
                .fetch_optional(&db)
                .await
                .unwrap()
                .is_some();

            if subscription_exists {
                log::info!("Subscription already exists. Skipping.");
            } else {
                // Add the subscription to the database
                let subscription_query = r#"
                    INSERT INTO push_subscriptions
                        ( user_id, endpoint, p256dh, auth, enabled )
                    VALUES
                        ( $1, $2, $3, $4, $5 )
                    returning *
                "#;

                sqlx::query_as::<_, PushSubscription>(subscription_query)
                    .bind(user_id)
                    .bind(subscription.endpoint)
                    .bind(subscription.keys.p256dh)
                    .bind(subscription.keys.auth)
                    .bind(true)
                    .fetch_one(&db)
                    .await
                    .unwrap();
            }
        }
        Err(e) => log::error!("Error sending web push notification: {}", e),
    }

    Ok(Json(passback))
}

#[derive(Debug, Clone, FromRow)]
pub struct PushSubscription {
    pub id: i32,
    pub user_id: i32,
    pub endpoint: String,
    pub p256dh: String,
    pub auth: String,
}

impl PushSubscription {
    pub async fn send_message(&self, private_key: &str, message: &str) {
        let subscription_info = SubscriptionInfo::new(
            self.endpoint.clone(),
            self.p256dh.clone(),
            self.auth.clone(),
        );

        let config = Config::new(
            CharacterSet::Standard,
            false,
        );

        let sig_builder = VapidSignatureBuilder::from_base64(
            private_key,
            config,
            &subscription_info,
        ).unwrap().build().unwrap();

        let mut builder = WebPushMessageBuilder::new(&subscription_info).unwrap();
        builder.set_payload(ContentEncoding::Aes128Gcm, message.as_bytes());
        builder.set_vapid_signature(sig_builder);

        let client = WebPushClient::new().unwrap();
        match client.send(builder.build().unwrap()).await {
            Ok(_) => {
                log::info!("Successfully sent web push notification to user {}", self.user_id);
            }
            Err(e) => log::error!("Error sending web push notification: {}", e),
        }
    }
}