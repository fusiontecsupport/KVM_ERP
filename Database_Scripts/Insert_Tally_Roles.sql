-- =============================================
-- Insert Roles for Tally Menu in KVM_ERP
-- RMenuGroupId = 2 (Tally Menu)
-- Each Tally item has 4 actions: Index, Create, Edit, Delete
-- Total: 4 Records (1 Tally item × 4 Actions)
-- =============================================

-- Clear existing Tally roles if needed (OPTIONAL - COMMENT OUT IF NOT NEEDED)
-- DELETE FROM AspNetRoles WHERE RMenuGroupId = 2;

-- =============================================
-- 1. INVOICE UPDATION TO TALLY (Order: 1)
-- =============================================
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'TallyInvoiceUpdationIndex', 'Can View Invoice Updation to Tally', 'ApplicationRole', 'Invoice Updation to Tally', 'TallyInvoiceUpdation', 2, 1, 'Index', 1, 'fa fa-sync-alt'),
(NEWID(), 'TallyInvoiceUpdationCreate', 'Can Create Invoice Updation to Tally', 'ApplicationRole', 'Invoice Updation to Tally', 'TallyInvoiceUpdation', 2, 1, 'Create', 1, 'fa fa-sync-alt'),
(NEWID(), 'TallyInvoiceUpdationEdit', 'Can Edit Invoice Updation to Tally', 'ApplicationRole', 'Invoice Updation to Tally', 'TallyInvoiceUpdation', 2, 1, 'Edit', 1, 'fa fa-sync-alt'),
(NEWID(), 'TallyInvoiceUpdationDelete', 'Can Delete Invoice Updation to Tally', 'ApplicationRole', 'Invoice Updation to Tally', 'TallyInvoiceUpdation', 2, 1, 'Delete', 1, 'fa fa-sync-alt');

-- =============================================
-- VERIFICATION QUERY
-- Run this to verify all 4 roles were inserted
-- =============================================
SELECT 
    RMenuGroupId,
    RMenuGroupOrder,
    RMenuType,
    RControllerName,
    RMenuIndex,
    Name,
    Description,
    RImageClassName
FROM AspNetRoles
WHERE RMenuGroupId = 2
ORDER BY RMenuGroupOrder, 
    CASE RMenuIndex 
        WHEN 'Index' THEN 1 
        WHEN 'Create' THEN 2 
        WHEN 'Edit' THEN 3 
        WHEN 'Delete' THEN 4 
    END;

-- Expected Result: 4 rows (1 tally item × 4 actions)

-- =============================================
-- TALLY MENU STRUCTURE SUMMARY
-- =============================================
/*
Tally Menu (RMenuGroupId = 2):
┌─────┬────────────────────────────┬─────────────────────────┬───────┬─────────────────┐
│ Ord │ Tally Item Name            │ Controller              │ Order │ Icon            │
├─────┼────────────────────────────┼─────────────────────────┼───────┼─────────────────┤
│  1  │ Invoice Updation to Tally  │ TallyInvoiceUpdation    │   1   │ fa fa-sync-alt  │
└─────┴────────────────────────────┴─────────────────────────┴───────┴─────────────────┘

Each Tally item has 4 permissions:
- Index  (View)
- Create (Add New)
- Edit   (Modify)
- Delete (Remove)

Total: 4 role records for Tally menu
*/
