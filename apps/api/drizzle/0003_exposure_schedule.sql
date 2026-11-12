ALTER TABLE "targets" ADD COLUMN "exposure_schedule" text DEFAULT 'off' NOT NULL;--> statement-breakpoint
ALTER TABLE "targets" ADD COLUMN "exposure_checked_at" timestamp with time zone;