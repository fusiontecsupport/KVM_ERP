-- =============================================
-- INSERT INITIAL PURCHASE INVOICE STATUSES
-- =============================================
-- This script inserts common invoice statuses
-- into the PURCHASEINVOICESTATUS table
-- =============================================

USE [KVM_ERP]
GO

PRINT '========================================';
PRINT 'INSERTING PURCHASE INVOICE STATUSES';
PRINT '========================================';

-- Check if table exists
IF EXISTS (SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'PURCHASEINVOICESTATUS')
BEGIN
    PRINT 'Table PURCHASEINVOICESTATUS found';
    
    -- Insert statuses only if they don't exist
    IF NOT EXISTS (SELECT 1 FROM PURCHASEINVOICESTATUS WHERE PUINSTCODE = 'PENDING')
    BEGIN
        INSERT INTO PURCHASEINVOICESTATUS (PUINSTDESC, PUINSTCODE, CUSRID, DISPSTATUS, PRCSDATE)
        VALUES ('Waiting for Approval', 'PENDING', 'SYSTEM', 0, GETDATE());
        PRINT '✅ Added: Waiting for Approval';
    END
    ELSE
    BEGIN
        PRINT '○ Already exists: Waiting for Approval';
    END
    
    IF NOT EXISTS (SELECT 1 FROM PURCHASEINVOICESTATUS WHERE PUINSTCODE = 'APPROVED')
    BEGIN
        INSERT INTO PURCHASEINVOICESTATUS (PUINSTDESC, PUINSTCODE, CUSRID, DISPSTATUS, PRCSDATE)
        VALUES ('Approved', 'APPROVED', 'SYSTEM', 0, GETDATE());
        PRINT '✅ Added: Approved';
    END
    ELSE
    BEGIN
        PRINT '○ Already exists: Approved';
    END
    
    IF NOT EXISTS (SELECT 1 FROM PURCHASEINVOICESTATUS WHERE PUINSTCODE = 'CANCELLED')
    BEGIN
        INSERT INTO PURCHASEINVOICESTATUS (PUINSTDESC, PUINSTCODE, CUSRID, DISPSTATUS, PRCSDATE)
        VALUES ('Cancel', 'CANCELLED', 'SYSTEM', 0, GETDATE());
        PRINT '✅ Added: Cancel';
    END
    ELSE
    BEGIN
        PRINT '○ Already exists: Cancel';
    END
    
    IF NOT EXISTS (SELECT 1 FROM PURCHASEINVOICESTATUS WHERE PUINSTCODE = 'REJECTED')
    BEGIN
        INSERT INTO PURCHASEINVOICESTATUS (PUINSTDESC, PUINSTCODE, CUSRID, DISPSTATUS, PRCSDATE)
        VALUES ('Rejected', 'REJECTED', 'SYSTEM', 0, GETDATE());
        PRINT '✅ Added: Rejected';
    END
    ELSE
    BEGIN
        PRINT '○ Already exists: Rejected';
    END
    
    IF NOT EXISTS (SELECT 1 FROM PURCHASEINVOICESTATUS WHERE PUINSTCODE = 'PROCESSING')
    BEGIN
        INSERT INTO PURCHASEINVOICESTATUS (PUINSTDESC, PUINSTCODE, CUSRID, DISPSTATUS, PRCSDATE)
        VALUES ('Processing', 'PROCESSING', 'SYSTEM', 0, GETDATE());
        PRINT '✅ Added: Processing';
    END
    ELSE
    BEGIN
        PRINT '○ Already exists: Processing';
    END
    
    IF NOT EXISTS (SELECT 1 FROM PURCHASEINVOICESTATUS WHERE PUINSTCODE = 'COMPLETED')
    BEGIN
        INSERT INTO PURCHASEINVOICESTATUS (PUINSTDESC, PUINSTCODE, CUSRID, DISPSTATUS, PRCSDATE)
        VALUES ('Completed', 'COMPLETED', 'SYSTEM', 0, GETDATE());
        PRINT '✅ Added: Completed';
    END
    ELSE
    BEGIN
        PRINT '○ Already exists: Completed';
    END
    
    PRINT '';
    PRINT '========================================';
    PRINT 'VERIFICATION - ALL STATUSES';
    PRINT '========================================';
    
    -- Display all statuses
    SELECT 
        PUINSTID,
        PUINSTDESC AS [Status Description],
        PUINSTCODE AS [Status Code],
        CASE WHEN DISPSTATUS = 0 THEN 'Active' ELSE 'Inactive' END AS [Display Status]
    FROM PURCHASEINVOICESTATUS
    ORDER BY PUINSTID;
    
END
ELSE
BEGIN
    PRINT '❌ ERROR: Table PURCHASEINVOICESTATUS does not exist!';
    PRINT 'Please create the table first using the CREATE TABLE script.';
END

PRINT '';
PRINT '========================================';
PRINT '✅ Script execution completed';
PRINT '========================================';

GO
