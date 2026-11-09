ALTER TABLE "findings" ADD COLUMN "secret_status" text;--> statement-breakpoint
ALTER TABLE "findings" ADD COLUMN "secret_checked_at" timestamp with time zone;