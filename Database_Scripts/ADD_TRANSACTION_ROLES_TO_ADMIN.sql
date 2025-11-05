-- =============================================
-- ADD TRANSACTION ROLES TO ADMIN GROUP
-- =============================================
-- This adds all Transaction menu roles to Admin group (GroupId = 2)
-- Based on Insert_Transaction_Menu_Roles.sql structure
-- =============================================

DECLARE @GroupId INT = 2;  -- Admin (change to 1 for SuperAdmin, 3 for Manager, 4 for Users)

-- Step 1: Get all transaction role IDs
DECLARE @RawMaterialsIntakeIndex NVARCHAR(128);
DECLARE @RawMaterialsIntakeCreate NVARCHAR(128);
DECLARE @RawMaterialsIntakeEdit NVARCHAR(128);
DECLARE @RawMaterialsIntakeDelete NVARCHAR(128);
DECLARE @RawMaterialsIntakePrint NVARCHAR(128);
DECLARE @RawMaterialsIntakeCalculationPrint NVARCHAR(128);
DECLARE @StockViewIndex NVARCHAR(128);
DECLARE @PurchaseInvoiceIndex NVARCHAR(128);
DECLARE @PurchaseInvoiceCreate NVARCHAR(128);
DECLARE @PurchaseInvoiceEdit NVARCHAR(128);
DECLARE @PurchaseInvoiceDelete NVARCHAR(128);
DECLARE @PurchaseInvoicePrint NVARCHAR(128);

SELECT @RawMaterialsIntakeIndex = Id FROM AspNetRoles WHERE Name = 'RawMaterialsIntakeIndex';
SELECT @RawMaterialsIntakeCreate = Id FROM AspNetRoles WHERE Name = 'RawMaterialsIntakeCreate';
SELECT @RawMaterialsIntakeEdit = Id FROM AspNetRoles WHERE Name = 'RawMaterialsIntakeEdit';
SELECT @RawMaterialsIntakeDelete = Id FROM AspNetRoles WHERE Name = 'RawMaterialsIntakeDelete';
SELECT @RawMaterialsIntakePrint = Id FROM AspNetRoles WHERE Name = 'RawMaterialsIntakePrint';
SELECT @RawMaterialsIntakeCalculationPrint = Id FROM AspNetRoles WHERE Name = 'RawMaterialsIntakeCalculationPrint';
SELECT @StockViewIndex = Id FROM AspNetRoles WHERE Name = 'StockViewIndex';
SELECT @PurchaseInvoiceIndex = Id FROM AspNetRoles WHERE Name = 'PurchaseInvoiceIndex';
SELECT @PurchaseInvoiceCreate = Id FROM AspNetRoles WHERE Name = 'PurchaseInvoiceCreate';
SELECT @PurchaseInvoiceEdit = Id FROM AspNetRoles WHERE Name = 'PurchaseInvoiceEdit';
SELECT @PurchaseInvoiceDelete = Id FROM AspNetRoles WHERE Name = 'PurchaseInvoiceDelete';
SELECT @PurchaseInvoicePrint = Id FROM AspNetRoles WHERE Name = 'PurchaseInvoicePrint';

PRINT '========================================';
PRINT 'Transaction Roles Found:';
PRINT '========================================';
SELECT 'RawMaterialsIntakeIndex' AS RoleName, @RawMaterialsIntakeIndex AS RoleId WHERE @RawMaterialsIntakeIndex IS NOT NULL
UNION ALL SELECT 'RawMaterialsIntakeCreate', @RawMaterialsIntakeCreate WHERE @RawMaterialsIntakeCreate IS NOT NULL
UNION ALL SELECT 'RawMaterialsIntakeEdit', @RawMaterialsIntakeEdit WHERE @RawMaterialsIntakeEdit IS NOT NULL
UNION ALL SELECT 'RawMaterialsIntakeDelete', @RawMaterialsIntakeDelete WHERE @RawMaterialsIntakeDelete IS NOT NULL
UNION ALL SELECT 'RawMaterialsIntakePrint', @RawMaterialsIntakePrint WHERE @RawMaterialsIntakePrint IS NOT NULL
UNION ALL SELECT 'RawMaterialsIntakeCalculationPrint', @RawMaterialsIntakeCalculationPrint WHERE @RawMaterialsIntakeCalculationPrint IS NOT NULL
UNION ALL SELECT 'StockViewIndex', @StockViewIndex WHERE @StockViewIndex IS NOT NULL
UNION ALL SELECT 'PurchaseInvoiceIndex', @PurchaseInvoiceIndex WHERE @PurchaseInvoiceIndex IS NOT NULL
UNION ALL SELECT 'PurchaseInvoiceCreate', @PurchaseInvoiceCreate WHERE @PurchaseInvoiceCreate IS NOT NULL
UNION ALL SELECT 'PurchaseInvoiceEdit', @PurchaseInvoiceEdit WHERE @PurchaseInvoiceEdit IS NOT NULL
UNION ALL SELECT 'PurchaseInvoiceDelete', @PurchaseInvoiceDelete WHERE @PurchaseInvoiceDelete IS NOT NULL
UNION ALL SELECT 'PurchaseInvoicePrint', @PurchaseInvoicePrint WHERE @PurchaseInvoicePrint IS NOT NULL;

-- Step 2: Create a table to hold all role IDs
DECLARE @RolesToAdd TABLE (RoleName VARCHAR(100), RoleId NVARCHAR(128));

INSERT INTO @RolesToAdd VALUES ('RawMaterialsIntakeIndex', @RawMaterialsIntakeIndex);
INSERT INTO @RolesToAdd VALUES ('RawMaterialsIntakeCreate', @RawMaterialsIntakeCreate);
INSERT INTO @RolesToAdd VALUES ('RawMaterialsIntakeEdit', @RawMaterialsIntakeEdit);
INSERT INTO @RolesToAdd VALUES ('RawMaterialsIntakeDelete', @RawMaterialsIntakeDelete);
INSERT INTO @RolesToAdd VALUES ('RawMaterialsIntakePrint', @RawMaterialsIntakePrint);
INSERT INTO @RolesToAdd VALUES ('RawMaterialsIntakeCalculationPrint', @RawMaterialsIntakeCalculationPrint);
INSERT INTO @RolesToAdd VALUES ('StockViewIndex', @StockViewIndex);
INSERT INTO @RolesToAdd VALUES ('PurchaseInvoiceIndex', @PurchaseInvoiceIndex);
INSERT INTO @RolesToAdd VALUES ('PurchaseInvoiceCreate', @PurchaseInvoiceCreate);
INSERT INTO @RolesToAdd VALUES ('PurchaseInvoiceEdit', @PurchaseInvoiceEdit);
INSERT INTO @RolesToAdd VALUES ('PurchaseInvoiceDelete', @PurchaseInvoiceDelete);
INSERT INTO @RolesToAdd VALUES ('PurchaseInvoicePrint', @PurchaseInvoicePrint);

-- Step 3: Add all roles to ApplicationRoleGroups
PRINT '========================================';
PRINT 'Adding roles to Admin group...';
PRINT '========================================';

DECLARE @RoleName VARCHAR(100);
DECLARE @RoleId NVARCHAR(128);
DECLARE @Added INT = 0;
DECLARE @Skipped INT = 0;

DECLARE role_cursor CURSOR FOR 
SELECT RoleName, RoleId FROM @RolesToAdd WHERE RoleId IS NOT NULL;

OPEN role_cursor;
FETCH NEXT FROM role_cursor INTO @RoleName, @RoleId;

WHILE @@FETCH_STATUS = 0
BEGIN
    IF NOT EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @GroupId AND RoleId = @RoleId)
    BEGIN
        INSERT INTO ApplicationRoleGroups (GroupId, RoleId)
        VALUES (@GroupId, @RoleId);
        PRINT '✓ Added: ' + @RoleName;
        SET @Added = @Added + 1;
    END
    ELSE
    BEGIN
        PRINT '○ Already exists: ' + @RoleName;
        SET @Skipped = @Skipped + 1;
    END
    
    FETCH NEXT FROM role_cursor INTO @RoleName, @RoleId;
END

CLOSE role_cursor;
DEALLOCATE role_cursor;

PRINT '========================================';
PRINT 'Summary:';
PRINT 'Added: ' + CAST(@Added AS VARCHAR(10)) + ' roles';
PRINT 'Skipped (already exist): ' + CAST(@Skipped AS VARCHAR(10)) + ' roles';
PRINT '========================================';

-- Step 4: Verify all roles are now assigned
PRINT '';
PRINT 'Verification - Transaction roles assigned to Admin:';
PRINT '========================================';

SELECT 
    arg.GroupId,
    g.Name AS GroupName,
    r.Name AS RoleName,
    r.Description
FROM ApplicationRoleGroups arg
INNER JOIN Groups g ON arg.GroupId = g.Id
INNER JOIN AspNetRoles r ON arg.RoleId = r.Id
WHERE arg.GroupId = @GroupId
  AND r.Name LIKE '%RawMaterialsIntake%' OR r.Name LIKE '%StockView%' OR r.Name LIKE '%PurchaseInvoice%'
ORDER BY r.Name;

PRINT '';
PRINT '========================================';
PRINT '✅ Done! Transaction roles added to Admin group.';
PRINT '⚠️  Now LOGOUT and LOGIN to refresh roles in session.';
PRINT '========================================';
