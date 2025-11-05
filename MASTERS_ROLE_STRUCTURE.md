# Role-Based Access Control Structure - KVM_ERP

## Overview
This document outlines the complete structure for implementing role-based access control for Transaction Menu and 16 Masters in KVM_ERP system.

## Menu Group IDs
- **1** = Transaction (3 items)
- **2** = Tally
- **3** = Reports
- **4** = Masters (16 items)

---

## Transaction Menu Mapping

### All Transaction Items (RMenuGroupId = 1)

| Order | Transaction Name | Controller Name | Action | RMenuGroupId | RMenuGroupOrder | Icon Class |
|-------|------------------|-----------------|--------|--------------|-----------------|------------|
| 1 | Raw Material Intake | RawMaterialIntake | Index | 1 | 1 | fa fa-truck-loading |
| 2 | Stock View | StockView | Index | 1 | 2 | fa fa-chart-line |
| 3 | Invoice | RawMaterialInvoice | Index | 1 | 3 | fa fa-file-invoice |

**Total Transaction Items:** 3  
**Total Roles:** 12 (3 transactions × 4 actions each)

### Transaction Role Examples:

```sql
-- Raw Material Intake - View Permission
Name: 'RawMaterialIntakeIndex'
RControllerName: 'RawMaterialIntake'
RMenuGroupId: 1
RMenuGroupOrder: 1

-- Raw Material Intake - Create Permission
Name: 'RawMaterialIntakeCreate'
RControllerName: 'RawMaterialIntake'
RMenuGroupId: 1
RMenuGroupOrder: 1
```

---

## Tally Menu Mapping

### All Tally Items (RMenuGroupId = 2)

| Order | Tally Item Name | Controller Name | Action | RMenuGroupId | RMenuGroupOrder | Icon Class |
|-------|-----------------|-----------------|--------|--------------|-----------------|------------|
| 1 | Invoice Updation to Tally | TallyInvoiceUpdation | Index | 2 | 1 | fa fa-sync-alt |

**Total Tally Items:** 1  
**Total Roles:** 4 (1 tally item × 4 actions each)

### Tally Role Examples:

```sql
-- Tally Invoice Updation - View Permission
Name: 'TallyInvoiceUpdationIndex'
RControllerName: 'TallyInvoiceUpdation'
RMenuGroupId: 2
RMenuGroupOrder: 1

-- Tally Invoice Updation - Create Permission
Name: 'TallyInvoiceUpdationCreate'
RControllerName: 'TallyInvoiceUpdation'
RMenuGroupId: 2
RMenuGroupOrder: 1
```

---

## Reports Menu Mapping

### All Report Items (RMenuGroupId = 3)

| Order | Report Name | Controller Name | Action | RMenuGroupId | RMenuGroupOrder | Icon Class |
|-------|-------------|-----------------|--------|--------------|-----------------|------------|
| 1 | Raw Materials Import Report | Reports | Index | 3 | 1 | fa fa-file-excel |

**Total Report Items:** 1  
**Total Roles:** 4 (1 report × 4 actions each)

### Reports Role Examples:

```sql
-- Raw Materials Import Report - View Permission
Name: 'RawMaterialsImportReportIndex'
RControllerName: 'Reports'
RMenuGroupId: 3
RMenuGroupOrder: 1

-- Raw Materials Import Report - Create Permission
Name: 'RawMaterialsImportReportCreate'
RControllerName: 'Reports'
RMenuGroupId: 3
RMenuGroupOrder: 1
```

---

## Complete Masters Mapping

### GENERAL Section (Orders 1-7)

| Order | Master Name | Controller Name | Action | RMenuGroupId | RMenuGroupOrder | Icon Class |
|-------|-------------|-----------------|--------|--------------|-----------------|------------|
| 1 | Company Master | CompanyMaster | Index | 4 | 1 | fa fa-building |
| 2 | Designation | DesginationMaster | Index | 4 | 2 | fa fa-id-badge |
| 3 | Department | DepartmentMaster | Index | 4 | 3 | fa fa-sitemap |
| 4 | Cost Factor | CostFactorMaster | Index | 4 | 4 | fa fa-calculator |
| 5 | HSN Code | HSNCodeMaster | Index | 4 | 5 | fa fa-barcode |
| 6 | Customer Master | CustomerMaster | Index | 4 | 6 | fa-solid fa-person |
| 7 | Supplier Master | SupplierMaster | Index | 4 | 7 | fa fa-truck |

### OTHERS Section (Orders 8-9)

| Order | Master Name | Controller Name | Action | RMenuGroupId | RMenuGroupOrder | Icon Class |
|-------|-------------|-----------------|--------|--------------|-----------------|------------|
| 8 | Location Master | LocationMaster | Index | 4 | 8 | fa-solid fa-map-location-dot |
| 9 | State Master | StateMaster | Index | 4 | 9 | fa-solid fa-compass |

### ITEM DETAILS Section (Orders 10-16)

| Order | Master Name | Controller Name | Action | RMenuGroupId | RMenuGroupOrder | Icon Class |
|-------|-------------|-----------------|--------|--------------|-----------------|------------|
| 10 | Unit | UnitMaster | Index | 4 | 10 | fa fa-balance-scale |
| 11 | Material | MaterialMaster | Index | 4 | 11 | fa-solid fa-atom |
| 12 | Material Type | MaterialTypeMaster | Index | 4 | 12 | fa fa-cubes |
| 13 | Material Group | MaterialGroupMaster | Index | 4 | 13 | fa fa-layer-group |
| 14 | Packing | PackingMaster | Index | 4 | 14 | fa fa-box |
| 15 | Packing Type | PackingTypeMaster | Index | 4 | 15 | fa fa-cube |
| 16 | Laboratory | LaboratoryMaster | Index | 4 | 16 | fa fa-flask |

---

## How to Create Roles in AspNetRoles Table

When adding a role for any of these 16 masters, use the following structure:

```sql
INSERT INTO AspNetRoles (Id, Name, Description, SDPTID, RMenuType, RControllerName, RMenuIndex, RMenuGroupId, RMenuGroupOrder, RImageClassName)
VALUES (
    NEWID(),                    -- Generate new GUID for Id
    'StateMaster-Create',       -- Role Name (format: ControllerName-Action)
    'State Master Create',      -- Description
    1,                          -- SDPTID (Department ID)
    'Masters',                  -- RMenuType (Always "Masters" for these 16)
    'StateMaster',              -- RControllerName (from table above)
    'Index',                    -- RMenuIndex (Action name, usually "Index")
    4,                          -- RMenuGroupId (Always 4 for Masters)
    9,                          -- RMenuGroupOrder (from table above)
    'fa-solid fa-compass'       -- RImageClassName (Icon from table above)
);
```

### Example Roles for Each Master:

#### State Master Example (Order 9):
```sql
-- View Permission
Name: 'StateMaster-Index'
RControllerName: 'StateMaster'
RMenuGroupId: 4
RMenuGroupOrder: 9
RMenuIndex: 'Index'

-- Create Permission
Name: 'StateMaster-Create'
RControllerName: 'StateMaster'
RMenuGroupId: 4
RMenuGroupOrder: 9
RMenuIndex: 'Create'

-- Edit Permission
Name: 'StateMaster-Edit'
RControllerName: 'StateMaster'
RMenuGroupId: 4
RMenuGroupOrder: 9
RMenuIndex: 'Edit'

-- Delete Permission
Name: 'StateMaster-Delete'
RControllerName: 'StateMaster'
RMenuGroupId: 4
RMenuGroupOrder: 9
RMenuIndex: 'Delete'
```

---

## Permission Assignment Flow

1. **Create Roles** → Add roles in Roles menu using the structure above
2. **Assign to Groups** → Go to Groups → Select a group → Permissions
3. **Grant Specific Access** → Check only the permissions you want to grant
   - Example: For "User" group, only check "StateMaster-Create" 
   - Users in this group can ONLY add new states, cannot edit/delete/view
4. **Users Inherit** → Users assigned to that group automatically get those permissions

---

## Navigation Structure

### Navbar → Masters Menu → Three Sections:

**Left Column (GENERAL):**
- Company Master (1)
- Designation (2)
- Department (3)
- Cost Factor (4)
- HSN Code (5)
- Customer Master (6)
- Supplier Master (7)

**Right Column (OTHERS):**
- Location Master (8)
- State Master (9)

**Right Column (ITEM DETAILS):**
- Unit (10)
- Material (11)
- Material Type (12)
- Material Group (13)
- Packing (14)
- Packing Type (15)
- Laboratory (16)

---

## Data Attributes in Navbar

Each master menu item now includes:
```html
<a class="dropdown-item" 
   href="@Url.Action("Index", "StateMaster")"
   data-role="StateMaster" 
   data-menugroupid="4" 
   data-menuorder="9">
    <i class="fa-solid fa-compass"></i> State Master
</a>
```

These attributes enable dynamic role-based filtering and permission checking.

---

## Implementation Status

✅ All 16 masters structured with proper metadata
✅ RMenuGroupId = 4 assigned to all
✅ RMenuGroupOrder = 1-16 (sequential)
✅ Data attributes added to navbar
✅ Ready for role-based permission system

---

## Files Modified

- `Views/Shared/_navbar.cshtml` - Added role metadata to all 16 masters
- This documentation file created for reference

---

## Next Steps for Implementation

1. ✅ **Structure Complete** - All 16 masters properly configured
2. ⏳ **Create Roles** - Add roles for each master's actions (Index, Create, Edit, Delete) in Roles menu
3. ⏳ **Assign Permissions** - Use Groups → Permissions to assign roles to groups
4. ⏳ **Test Access Control** - Login as different users and verify permissions work correctly

---

**Last Updated:** November 5, 2025
**Project:** KVM_ERP - MARINEX
**Purpose:** Role-Based Access Control for 16 Masters
