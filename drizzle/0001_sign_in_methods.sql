CREATE TABLE "authorization_codes" (
	"code_hash" text PRIMARY KEY NOT NULL,
	"client_id" text NOT NULL,
	"redirect_uri" text NOT NULL,
	"code_challenge" text NOT NULL,
	"session_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"expires_at" timestamp (3) with time zone NOT NULL,
	"consumed_at" timestamp (3) with time zone,
	"created_at" timestamp (3) with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "grants" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"user_id" uuid NOT NULL,
	"service" text NOT NULL,
	"plan" text NOT NULL,
	"source" text NOT NULL,
	"source_ref" text NOT NULL,
	"source_version" integer NOT NULL,
	"valid_until" timestamp (3) with time zone,
	"revoked_at" timestamp (3) with time zone,
	"created_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "grants_service_format" CHECK ("grants"."service" ~ '^[a-z][a-z0-9-]{1,30}$'),
	CONSTRAINT "grants_plan_format" CHECK ("grants"."plan" ~ '^[a-z][a-z0-9-]{1,30}$')
);
--> statement-breakpoint
CREATE TABLE "identities" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"user_id" uuid NOT NULL,
	"provider" text NOT NULL,
	"subject" text NOT NULL,
	"email" text,
	"created_at" timestamp (3) with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "passkeys" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"user_id" uuid NOT NULL,
	"credential_id" text NOT NULL,
	"public_key" "bytea" NOT NULL,
	"sign_count" bigint DEFAULT 0 NOT NULL,
	"transports" text[] DEFAULT '{}'::text[] NOT NULL,
	"aaguid" text NOT NULL,
	"rp_id" text NOT NULL,
	"backup_eligible" boolean NOT NULL,
	"backed_up" boolean NOT NULL,
	"name" text NOT NULL,
	"created_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	"last_used_at" timestamp (3) with time zone,
	CONSTRAINT "passkeys_name_length" CHECK (char_length("passkeys"."name") between 1 and 60)
);
--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "client_id" text;--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "parent_session_id" uuid;--> statement-breakpoint
ALTER TABLE "authorization_codes" ADD CONSTRAINT "authorization_codes_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "grants" ADD CONSTRAINT "grants_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identities" ADD CONSTRAINT "identities_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "passkeys" ADD CONSTRAINT "passkeys_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "authorization_codes_expires_idx" ON "authorization_codes" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "grants_source_uq" ON "grants" USING btree ("source","source_ref");--> statement-breakpoint
CREATE INDEX "grants_user_idx" ON "grants" USING btree ("user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "identities_provider_subject_uq" ON "identities" USING btree ("provider","subject");--> statement-breakpoint
CREATE UNIQUE INDEX "identities_user_provider_uq" ON "identities" USING btree ("user_id","provider");--> statement-breakpoint
CREATE UNIQUE INDEX "passkeys_credential_id_uq" ON "passkeys" USING btree ("credential_id");--> statement-breakpoint
CREATE INDEX "passkeys_user_idx" ON "passkeys" USING btree ("user_id","created_at");--> statement-breakpoint
CREATE INDEX "sessions_parent_idx" ON "sessions" USING btree ("parent_session_id") WHERE "sessions"."parent_session_id" is not null;