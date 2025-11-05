# Transaction Menu Roles Structure

## Overview
This document describes the role-based access control structure for the Transaction menu in KVM ERP system.

---

## Role Naming Convention
Format: `{ControllerName}{Action}`

Example:
- `RawMaterialIntakeIndex`
- `PurchaseInvoiceCreate`
- `StockViewPrint`

---

## Transaction Menu Items (RMenuGroupId = 1)

### 1. Raw Materials Intake (Order: 1)
**Controller**: `RawMaterialIntake`  
**Icon**: `fa fa-truck-loading`

| Role Name | Description | Action |
|-----------|-------------|--------|
| `RawMaterialIntakeIndex` | Can View Raw Materials Intake | Index (List/View) |
| `RawMaterialIntakeCreate` | Can Create Raw Materials Intake | Create (Add New) |
| `RawMaterialIntakeEdit` | Can Edit Raw Materials Intake | Edit (Modify) |
| `RawMaterialIntakeDelete` | Can Delete Raw Materials Intake | Delete (Remove) |
| `RawMaterialIntakePrint` | Can Print Raw Materials Intake | Print (Document) |
| `RawMaterialIntakeCalculationPrint` | Can Print Calculation for Raw Materials Intake | CalculationPrint (Calculation Document) |

**Total Roles**: 6

---

### 2. Stock View (Order: 2)
**Controller**: `StockView`  
**Icon**: `fa fa-boxes`

| Role Name | Description | Action |
|-----------|-------------|--------|
| `StockViewIndex` | Can View Stock | Index (List/View) |
| `StockViewPrint` | Can Print Stock View | Print (Document) |

**Total Roles**: 2

---

### 3. Invoice (Purchase Invoice) (Order: 3)
**Controller**: `PurchaseInvoice`  
**Icon**: `fa fa-file-invoice`

| Role Name | Description | Action |
|-----------|-------------|--------|
| `PurchaseInvoiceIndex` | Can View Purchase Invoice | Index (List/View) |
| `PurchaseInvoiceCreate` | Can Create Purchase Invoice | Create (Add New) |
| `PurchaseInvoiceEdit` | Can Edit Purchase Invoice | Edit (Modify) |
| `PurchaseInvoiceDelete` | Can Delete Purchase Invoice | Delete (Remove) |
| `PurchaseInvoicePrint` | Can Print Purchase Invoice | Print (Document) |

**Total Roles**: 5

---

### 4. Purchase Invoice Approval (NEW) (Order: 4)
**Controller**: `PurchaseInvoiceApproval`  
**Icon**: `fa fa-check-circle`

| Role Name | Description | Action |
|-----------|-------------|--------|
| `PurchaseInvoiceApprovalIndex` | Can View Purchase Invoice Approval | Index (List/View) |
| `PurchaseInvoiceApprovalEdit` | Can Edit Purchase Invoice Approval | Edit (Approve/Reject) |
| `PurchaseInvoiceApprovalPrint` | Can Print Purchase Invoice Approval | Print (Document) |

**Total Roles**: 3

---

## Summary Statistics

| Menu Item | Roles Count | Has Index | Has Create | Has Edit | Has Delete | Has Print | Special Actions |
|-----------|-------------|-----------|------------|----------|------------|-----------|-----------------|
| Raw Materials Intake | 6 | ✅ | ✅ | ✅ | ✅ | ✅ | CalculationPrint |
| Stock View | 2 | ✅ | ❌ | ❌ | ❌ | ✅ | - |
| Purchase Invoice | 5 | ✅ | ✅ | ✅ | ✅ | ✅ | - |
| Purchase Invoice Approval | 3 | ✅ | ❌ | ✅ | ❌ | ✅ | - |

**Total Transaction Menu Roles**: 16

---

## Database Structure

### AspNetRoles Table Columns Used:
- `Id` (GUID) - Unique identifier
- `Name` (string) - Role name (e.g., "RawMaterialIntakeIndex")
- `Description` (string) - Human-readable description
- `Discriminator` (string) - Always "ApplicationRole"
- `RMenuType` (string) - Display name (e.g., "Raw Materials Intake")
- `RControllerName` (string) - Controller name (e.g., "RawMaterialIntake")
- `RMenuGroupId` (int) - Menu group (1 = Transaction)
- `RMenuGroupOrder` (int) - Display order (1-4)
- `RMenuIndex` (string) - Action type (Index, Create, Edit, Delete, Print)
- `SDPTID` (int) - Always 1
- `RImageClassName` (string) - Font Awesome icon class

---

## Usage in Controllers

### Example: Raw Material Intake Controller

```csharp
[SessionExpire]
public class RawMaterialIntakeController : Controller
{
    // View list
    [Authorize(Roles = "RawMaterialIntakeIndex")]
    public ActionResult Index() { }

    // Add/Edit form
    public ActionResult Form(int id = 0)
    {
        if (id == 0)
        {
            // ADD - Check Create permission
            if (!User.IsInRole("RawMaterialIntakeCreate"))
                return RedirectToAction("Login", "Account");
        }
        else
        {
            // EDIT - Check Edit permission
            if (!User.IsInRole("RawMaterialIntakeEdit"))
                return RedirectToAction("Login", "Account");
        }
    }

    // Delete
    public string Del(int id)
    {
        if (!User.IsInRole("RawMaterialIntakeDelete"))
            return ""; // Unauthorized
        // ... delete logic
    }

    // Print
    [Authorize(Roles = "RawMaterialIntakePrint")]
    public ActionResult Print(int id) { }

    // Calculation Print
    [Authorize(Roles = "RawMaterialIntakeCalculationPrint")]
    public ActionResult CalculationPrint(int id) { }
}
```

---

## Navigation Bar Integration

### _navbar.cshtml Structure:

```html
<!-- Transaction Menu (RMenuGroupId = 1) -->
@if (isAdmin || User.IsInRole("RawMaterialIntakeIndex") || 
     User.IsInRole("StockViewIndex") || 
     User.IsInRole("PurchaseInvoiceIndex") ||
     User.IsInRole("PurchaseInvoiceApprovalIndex"))
{
    <li class="nav-item dropdown">
        <a class="nav-link dropdown-toggle" href="#" data-toggle="dropdown">
            <i class="fa fa-exchange-alt"></i> Transaction
        </a>
        <ul class="dropdown-menu">
            <!-- Raw Materials Intake -->
            @if (User.IsInRole("RawMaterialIntakeIndex"))
            {
                <li>
                    <a href="@Url.Action("Index", "RawMaterialIntake")">
                        <i class="fa fa-truck-loading"></i> Raw Materials Intake
                    </a>
                </li>
            }
            
            <!-- Stock View -->
            @if (User.IsInRole("StockViewIndex"))
            {
                <li>
                    <a href="@Url.Action("Index", "StockView")">
                        <i class="fa fa-boxes"></i> Stock View
                    </a>
                </li>
            }
            
            <!-- Purchase Invoice -->
            @if (User.IsInRole("PurchaseInvoiceIndex"))
            {
                <li>
                    <a href="@Url.Action("Index", "PurchaseInvoice")">
                        <i class="fa fa-file-invoice"></i> Invoice
                    </a>
                </li>
            }
            
            <!-- Purchase Invoice Approval -->
            @if (User.IsInRole("PurchaseInvoiceApprovalIndex"))
            {
                <li>
                    <a href="@Url.Action("Index", "PurchaseInvoiceApproval")">
                        <i class="fa fa-check-circle"></i> Purchase Invoice Approval
                    </a>
                </li>
            }
        </ul>
    </li>
}
```

---

## Permission Assignment Workflow

1. **Run SQL Script**: Execute `Insert_Transaction_Menu_Roles.sql` to create roles
2. **Assign to Groups**: In Groups → Permissions, select roles for each group
3. **User Login**: Users get roles from their group on login
4. **Menu Display**: Navigation shows only permitted menu items
5. **Action Access**: Controllers enforce permissions on each action

---

## Testing Checklist

### Raw Materials Intake:
- [ ] Index permission shows menu and allows viewing list
- [ ] Create permission allows adding new records
- [ ] Edit permission allows modifying existing records
- [ ] Delete permission allows removing records
- [ ] Print permission allows generating documents
- [ ] CalculationPrint permission allows calculation reports

### Stock View:
- [ ] Index permission shows menu and allows viewing stock
- [ ] Print permission allows printing stock reports

### Purchase Invoice:
- [ ] Index permission shows menu and allows viewing invoices
- [ ] Create permission allows creating new invoices
- [ ] Edit permission allows modifying invoices
- [ ] Delete permission allows removing invoices
- [ ] Print permission allows printing invoices

### Purchase Invoice Approval:
- [ ] Index permission shows menu and allows viewing approvals
- [ ] Edit permission allows approving/rejecting invoices
- [ ] Print permission allows printing approval documents

---

## Related Files

- **SQL Script**: `Insert_Transaction_Menu_Roles.sql`
- **Masters Roles**: `Insert_16_Masters_Roles.sql`
- **All Roles**: `Insert_ALL_Menu_Roles_Complete.sql` (if exists)

---

## Notes

1. **Logout Required**: After assigning new permissions, users must logout and login for changes to take effect
2. **Session Caching**: Roles are cached in session on login
3. **Index Permission**: Required to see menu item in navigation
4. **Create vs Edit**: Always check separately in Form action based on `id` parameter
5. **Print Actions**: Separate permissions for different print types

---

**Last Updated**: 2025-11-05  
**Version**: 1.0
