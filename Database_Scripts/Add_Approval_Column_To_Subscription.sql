USE [KVM_ERP]
GO

-- Check if Approval column exists
IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID(N'[dbo].[Subscription]') AND name = 'Approval')
BEGIN
    -- Add Approval column to Subscription table as bit (boolean)
    ALTER TABLE [dbo].[Subscription]
    ADD [Approval] [bit] NOT NULL DEFAULT(1)
    
    PRINT 'Approval column added to Subscription table successfully.'
END
ELSE
BEGIN
    PRINT 'Approval column already exists in Subscription table.'
END
GO

-- Update existing records to have Approval = 1 (True/Approved) by default
UPDATE [dbo].[Subscription] 
SET [Approval] = 1 
WHERE [Approval] IS NULL OR [Approval] = 0

PRINT 'Updated existing subscription records to Approved status.'
GO

-- Create index for better performance on Approval lookups
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_Subscription_Approval_UserId')
BEGIN
    CREATE NONCLUSTERED INDEX [IX_Subscription_Approval_UserId] ON [dbo].[Subscription]
    (
        [UserId] ASC,
        [Approval] ASC,
        [IsActive] ASC
    )
    INCLUDE ([ExpiryDate], [PlanName])
    
    PRINT 'Index created for Approval and UserId columns.'
END
ELSE
BEGIN
    PRINT 'Index for Approval and UserId columns already exists.'
END
GO

PRINT 'Subscription table Approval column setup completed successfully.'
PRINT 'Approval Values: 1 (True) = Approved, 0 (False) = Not Approved'
