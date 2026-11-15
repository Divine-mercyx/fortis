CREATE TABLE "billing_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"event_key" text NOT NULL,
	"type" text NOT NULL,
	"reference" text,
	"received_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "billing_payments" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" uuid NOT NULL,
	"reference" text NOT NULL,
	"kind" text NOT NULL,
	"plan" text NOT NULL,
	"amount_kobo" bigint NOT NULL,
	"vat_kobo" bigint DEFAULT 0 NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"channel" text,
	"failure_reason" text,
	"period_start" timestamp with time zone,
	"period_end" timestamp with time zone,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"paid_at" timestamp with time zone,
	"receipt_sent_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "billing_subscriptions" (
	"org_id" uuid PRIMARY KEY NOT NULL,
	"plan" text NOT NULL,
	"status" text NOT NULL,
	"current_period_start" timestamp with time zone NOT NULL,
	"current_period_end" timestamp with time zone NOT NULL,
	"cancel_at_period_end" boolean DEFAULT false NOT NULL,
	"next_plan" text,
	"authorization" text,
	"card_brand" text,
	"card_last4" text,
	"card_exp" text,
	"billing_email" text NOT NULL,
	"grace_ends_at" timestamp with time zone,
	"failed_attempts" integer DEFAULT 0 NOT NULL,
	"last_attempt_at" timestamp with time zone,
	"reminder_sent_at" timestamp with time zone,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "billing_payments" ADD CONSTRAINT "billing_payments_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "billing_payments" ADD CONSTRAINT "billing_payments_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "billing_subscriptions" ADD CONSTRAINT "billing_subscriptions_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "billing_events_key" ON "billing_events" USING btree ("event_key");--> statement-breakpoint
CREATE UNIQUE INDEX "billing_payments_reference_key" ON "billing_payments" USING btree ("reference");--> statement-breakpoint
CREATE INDEX "billing_payments_org_idx" ON "billing_payments" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "billing_subscriptions_due_idx" ON "billing_subscriptions" USING btree ("status","current_period_end");