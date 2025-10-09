-- Add CALCULATIONMODE column to TRANSACTION_PRODUCT_CALCULATION table
-- This column stores the calculation mode selected by user
-- Values: 1 = Packing, 2 = Grade Weight

USE [KVM_ERP]
GO

-- Check if column already exists
IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.COLUMNS 
               WHERE TABLE_NAME = 'TRANSACTION_PRODUCT_CALCULATION' 
               AND COLUMN_NAME = 'CALCULATIONMODE')
BEGIN
    PRINT 'Adding CALCULATIONMODE column...'
    
    -- Add the CALCULATIONMODE column as INT with default value
    ALTER TABLE [dbo].[TRANSACTION_PRODUCT_CALCULATION]
    ADD [CALCULATIONMODE] INT NULL DEFAULT 1
    
    PRINT 'CALCULATIONMODE column added successfully to TRANSACTION_PRODUCT_CALCULATION table'
    
    -- Update any existing NULL values to default (1 = Packing)
    UPDATE [dbo].[TRANSACTION_PRODUCT_CALCULATION]
    SET [CALCULATIONMODE] = 1
    WHERE [CALCULATIONMODE] IS NULL
    
    PRINT 'Default values applied to existing records'
END
ELSE
BEGIN
    PRINT 'CALCULATIONMODE column already exists in TRANSACTION_PRODUCT_CALCULATION table'
END
GO

-- Verify the column was added
PRINT 'Verifying column creation...'
SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT
FROM INFORMATION_SCHEMA.COLUMNS 
WHERE TABLE_NAME = 'TRANSACTION_PRODUCT_CALCULATION' 
AND COLUMN_NAME = 'CALCULATIONMODE'

-- Show the values meaning
PRINT ''
PRINT 'CALCULATIONMODE Values:'
PRINT '1 = Packing (Full calculation with all fields)'
PRINT '2 = Grade Weight (Simple: Slab + Peeled only)'
GO
