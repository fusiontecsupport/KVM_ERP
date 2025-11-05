# Master Controllers - Role Authorization Update

## Issue
Several Master controllers were using hardcoded `[Authorize(Roles = "Admin")]` instead of specific role names, causing authorization failures even after roles were added to the database and assigned to user groups.

## Solution
Updated all Master controllers to use specific role-based authorization matching the role names in the database.

---

## Updated Controllers

### ✅ 1. DesginationMasterController.cs
- **Index**: `[Authorize(Roles = "DesginationMasterIndex")]`
- **Form**: `[Authorize(Roles = "DesginationMasterCreate,DesginationMasterEdit")]`
- **Del**: `[Authorize(Roles = "DesginationMasterDelete")]`

### ✅ 2. DepartmentMasterController.cs
- **Index**: `[Authorize(Roles = "DepartmentMasterIndex")]`
- **Form**: `[Authorize(Roles = "DepartmentMasterCreate,DepartmentMasterEdit")]`
- **Del**: `[Authorize(Roles = "DepartmentMasterDelete")]`

### ✅ 3. CustomerMasterController.cs
- **Index**: `[Authorize(Roles = "CustomerMasterIndex")]`
- **Form**: `[Authorize(Roles = "CustomerMasterCreate,CustomerMasterEdit")]`

### ✅ 4. SupplierMasterController.cs
- **Index**: `[Authorize(Roles = "SupplierMasterIndex")]`
- **Form**: `[Authorize(Roles = "SupplierMasterCreate,SupplierMasterEdit")]`

### ✅ 5. LocationMasterController.cs
- **Index**: `[Authorize(Roles = "LocationMasterIndex")]`
- **Form**: `[Authorize(Roles = "LocationMasterCreate,LocationMasterEdit")]`
- **Del**: `[Authorize(Roles = "LocationMasterDelete")]`

### ✅ 6. LaboratoryMasterController.cs
- **Index**: `[Authorize(Roles = "LaboratoryMasterIndex")]`
- **Form**: `[Authorize(Roles = "LaboratoryMasterCreate,LaboratoryMasterEdit")]`

---

### ✅ 7. CostFactorMasterController.cs
- **Index**: `[Authorize(Roles = "CostFactorMasterIndex")]`
- **Form**: `[Authorize(Roles = "CostFactorMasterCreate,CostFactorMasterEdit")]`

### ✅ 8. HSNCodeMasterController.cs
- **Index**: `[Authorize(Roles = "HSNCodeMasterIndex")]`
- **Form**: `[Authorize(Roles = "HSNCodeMasterCreate,HSNCodeMasterEdit")]`

### ✅ 9. UnitMasterController.cs
- **Index**: `[Authorize(Roles = "UnitMasterIndex")]`
- **Form**: `[Authorize(Roles = "UnitMasterCreate,UnitMasterEdit")]`

### ✅ 10. MaterialMasterController.cs ⚠️ **CRITICAL SECURITY FIX**
- **Index**: `[Authorize(Roles = "MaterialMasterIndex")]`
- **Form**: `[Authorize(Roles = "MaterialMasterCreate,MaterialMasterEdit")]`
- **Added**: `[SessionExpire]` attribute (was completely missing!)

### ✅ 11. MaterialTypeMasterController.cs
- **Index**: `[Authorize(Roles = "MaterialTypeMasterIndex")]`
- **Form**: `[Authorize(Roles = "MaterialTypeMasterCreate,MaterialTypeMasterEdit")]`

### ✅ 12. MaterialGroupMasterController.cs
- **Index**: `[Authorize(Roles = "MaterialGroupMasterIndex")]`
- **Form**: `[Authorize(Roles = "MaterialGroupMasterCreate,MaterialGroupMasterEdit")]`

### ✅ 13. PackingMasterController.cs
- **Index**: `[Authorize(Roles = "PackingMasterIndex")]`
- **Form**: `[Authorize(Roles = "PackingMasterCreate,PackingMasterEdit")]`

### ✅ 14. PackingTypeMasterController.cs
- **Index**: `[Authorize(Roles = "PackingTypeMasterIndex")]`
- **Form**: `[Authorize(Roles = "PackingTypeMasterCreate,PackingTypeMasterEdit")]`

---

## Already Using Correct Roles

### ✅ CompanyMasterController.cs
- Already had `[Authorize(Roles = "CompanyMasterIndex")]`

### ✅ StateMasterController.cs
- Already had `[Authorize(Roles = "StateMasterIndex")]`

---

## Summary

**Total Controllers Updated:** 14 (out of 16 masters)

**Critical Issues Fixed:**
- MaterialMasterController had NO authorization whatsoever! ⚠️ Added `[SessionExpire]` and role-based authorization

**All 16 Masters Status:**
1. ✅ Company Master - Already correct
2. ✅ Designation - Fixed
3. ✅ Department - Fixed
4. ✅ Cost Factor - Fixed
5. ✅ HSN Code - Fixed
6. ✅ Customer Master - Fixed
7. ✅ Supplier Master - Fixed
8. ✅ Location Master - Fixed
9. ✅ State Master - Already correct
10. ✅ Unit Master - Fixed
11. ✅ Material Master - **CRITICAL FIX** (was completely open!)
12. ✅ Material Type - Fixed
13. ✅ Material Group - Fixed
14. ✅ Packing Master - Fixed
15. ✅ Packing Type - Fixed
16. ✅ Laboratory - Fixed

---

## Testing After Update

1. **Logout** from the application
2. **Login** again (to refresh session roles)
3. **Test each Master menu item**:
   - Company Master ✅
   - Designation ✅
   - Department ✅
   - Customer Master ✅
   - Supplier Master ✅
   - Location Master ✅
   - State Master ✅
   - Laboratory ✅

All should now work without redirecting to login page, assuming the roles are properly assigned to your group.

---

## Role Naming Convention

**Pattern**: `{ControllerName}{Action}`

Examples:
- `CompanyMasterIndex` → View Company Master
- `CompanyMasterCreate` → Create Company Master
- `CompanyMasterEdit` → Edit Company Master
- `CompanyMasterDelete` → Delete Company Master

---

## Important Notes

1. **Multiple Roles for Form**: The `Form` action allows both Create and Edit, so it requires EITHER role:
   ```csharp
   [Authorize(Roles = "CustomerMasterCreate,CustomerMasterEdit")]
   ```

2. **Role Assignment**: Ensure all these roles are:
   - ✅ Inserted in `AspNetRoles` table
   - ✅ Assigned to user's group in `ApplicationRoleGroups` table
   - ✅ User has logged out and back in after role assignment

3. **Session Refresh**: Users MUST logout and login after role changes to refresh their session.
