ALTER TABLE `targets`
    ADD COLUMN `department` VARCHAR(255),
    ADD COLUMN `role` VARCHAR(255),
    ADD COLUMN `company` VARCHAR(255),
    ADD COLUMN `manager_name` VARCHAR(255);

ALTER TABLE `results`
    ADD COLUMN `department` VARCHAR(255),
    ADD COLUMN `role` VARCHAR(255),
    ADD COLUMN `company` VARCHAR(255),
    ADD COLUMN `manager_name` VARCHAR(255);

ALTER TABLE `email_requests`
    ADD COLUMN `department` VARCHAR(255),
    ADD COLUMN `role` VARCHAR(255),
    ADD COLUMN `company` VARCHAR(255),
    ADD COLUMN `manager_name` VARCHAR(255);
