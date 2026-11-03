CREATE TABLE "targets" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" uuid NOT NULL,
	"project_id" uuid NOT NULL,
	"url" text NOT NULL,
	"hostname" text NOT NULL,
	"environment" text NOT NULL,
	"label" text,
	"verification_token" text NOT NULL,
	"verified_at" timestamp with time zone,
	"last_verification_error" text,
	"authorized_by" uuid,
	"authorized_signer" text,
	"authorization_version" text,
	"authorized_at" timestamp with time zone,
	"paused_at" timestamp with time zone,
	"last_run_at" timestamp with time zone,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "findings" ADD COLUMN "kind" text DEFAULT 'code' NOT NULL;--> statement-breakpoint
ALTER TABLE "findings" ADD COLUMN "target_id" uuid;--> statement-breakpoint
ALTER TABLE "findings" ADD COLUMN "detail" text;--> statement-breakpoint
ALTER TABLE "scans" ADD COLUMN "kind" text DEFAULT 'code' NOT NULL;--> statement-breakpoint
ALTER TABLE "scans" ADD COLUMN "target_id" uuid;--> statement-breakpoint
ALTER TABLE "scans" ADD COLUMN "dast_mode" text;--> statement-breakpoint
ALTER TABLE "targets" ADD CONSTRAINT "targets_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "targets" ADD CONSTRAINT "targets_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "targets" ADD CONSTRAINT "targets_authorized_by_users_id_fk" FOREIGN KEY ("authorized_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "targets" ADD CONSTRAINT "targets_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "targets_project_url_key" ON "targets" USING btree ("project_id","url");--> statement-breakpoint
CREATE INDEX "targets_org_idx" ON "targets" USING btree ("org_id");--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_target_id_targets_id_fk" FOREIGN KEY ("target_id") REFERENCES "public"."targets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scans" ADD CONSTRAINT "scans_target_id_targets_id_fk" FOREIGN KEY ("target_id") REFERENCES "public"."targets"("id") ON DELETE set null ON UPDATE no action;