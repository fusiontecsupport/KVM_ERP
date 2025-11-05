# TRANEQTY Implementation - Raw Material Invoice

## 📝 Overview

Implemented new `TRANEQTY` column to separate **Original Quantity** (from Raw Material Intake) from **Editable Invoice Quantity** in the Raw Material Invoice form.

---

## ✅ What Was Done

### **1. Database Model Updated** ✅

**TransactionDetail Model:**
- Added `TRANEQTY` property (numeric(18,3) NOT NULL)
- Added precision configuration in `ApplicationDbContext`

### **2. Controller Logic Updated** ✅

**RawMaterialInvoiceController.cs:**

#### **GetInvoiceItems Method:**
- Now loads `TRANEQTY` instead of `TRANDQTY` for NetWeight
- Shows editable quantity when editing invoices

#### **GetAllInvoiceItems Method:**
- Updated savedItems query to load `TRANEQTY`
- Merges correctly when showing available + saved items

#### **SaveInvoice Method:**
- **INSERT statement updated** to include `TRANEQTY`
- **Saves 3 quantities:**
  - `TRANAQTY` = Original/Actual weight from Raw Material Intake
  - `TRANEQTY` = Editable weight entered by user
  - `TRANDQTY` = Same as `TRANEQTY` (for compatibility)

---

## 🔄 Data Flow

### **When Loading Items (New Invoice):**

```
Raw Material Intake (REGSTRID=1)
    FACTORYWGT = 100 kg
         ↓
Raw Material Invoice Form (REGSTRID=2)
    Net Weight (kg) field shows: 100 kg (editable)
```

### **When User Edits Quantity:**

```
User changes Net Weight from 100 → 80

On Save:
    TRANAQTY = 100  (Original from Raw Material Intake)
    TRANEQTY = 80   (Edited value by user)
    TRANDQTY = 80   (Same as TRANEQTY)
```

### **When Editing Existing Invoice:**

```
Load from database:
    TRANAQTY = 100  (Original - read-only)
    TRANEQTY = 80   (Loads into Net Weight field - editable)
    
User can modify TRANEQTY and save again
```

---

## 📊 Column Mapping

| Column | Description | Source | Editable | Display in Form |
|--------|-------------|--------|----------|----------------|
| **TRANAQTY** | Original/Actual Weight | Raw Material Intake | ❌ No | Not shown in invoice form |
| **TRANEQTY** | Editable Invoice Weight | User Input | ✅ Yes | **"Net Weight (kg)"** field |
| **TRANDQTY** | Copy of TRANEQTY | Same as TRANEQTY | ❌ No | Used for compatibility |

---

## 💡 Example Scenario

### **Scenario: Deduction for Damage**

**Step 1: Raw Material Intake**
- Supplier delivers 100 kg of raw material
- Saved as `TRANAQTY = 100` in Raw Material Intake (REGSTRID=1)

**Step 2: Create Invoice**
- Load items for invoice
- Net Weight field shows: **100 kg** (loaded from `FACTORYWGT`)
- User notices 20 kg is damaged
- User edits Net Weight to: **80 kg**

**Step 3: Save Invoice**
```sql
INSERT INTO TRANSACTIONDETAIL (
    TRANAQTY,  -- 100 (original)
    TRANEQTY,  -- 80  (edited)
    TRANDQTY,  -- 80  (same as TRANEQTY)
    ...
)
```

**Step 4: Invoice Calculation**
- Amount calculation uses **TRANEQTY (80 kg)**
- Rate × 80 = Invoice Amount
- **History preserved:** TRANAQTY still shows original 100 kg

---

## 🎯 Benefits

### **1. Data Integrity** ✅
- Original quantity preserved in `TRANAQTY`
- Edited quantity stored separately in `TRANEQTY`
- Audit trail: Can compare original vs invoiced quantity

### **2. Flexibility** ✅
- Users can adjust invoice quantity without losing original data
- Useful for:
  - Damaged goods deduction
  - Quality rejection
  - Partial deliveries
  - Weight discrepancies

### **3. Backward Compatibility** ✅
- `TRANDQTY` still populated (same as `TRANEQTY`)
- Existing reports/queries continue to work
- No breaking changes to other parts of system

---

## 📁 Files Modified

| File | Lines | Change Description |
|------|-------|-------------------|
| `Models/TransactionDetail.cs` | 58-60 | Added TRANEQTY property |
| `Models/ApplicationDbContext.cs` | 149 | Added precision config for TRANEQTY |
| `Controllers/RawMaterialInvoiceController.cs` | 425 | GetInvoiceItems: Load TRANEQTY |
| `Controllers/RawMaterialInvoiceController.cs` | 541 | GetAllInvoiceItems: Load TRANEQTY |
| `Controllers/RawMaterialInvoiceController.cs` | 1047 | INSERT: Add TRANEQTY column |
| `Controllers/RawMaterialInvoiceController.cs` | 1078-1080 | Parameters: TRANAQTY, TRANDQTY, TRANEQTY |

---

## 🚀 Testing Steps

### **Test 1: Create New Invoice**
1. Go to Raw Material Invoice Form
2. Select a supplier
3. Items load with Net Weight = Actual Weight from intake
4. Edit Net Weight (e.g., 100 → 80)
5. Save invoice
6. **Verify in DB:**
   ```sql
   SELECT TRANAQTY, TRANEQTY, TRANDQTY, TRANDAMT
   FROM TRANSACTIONDETAIL
   WHERE TRANMID = [new_invoice_id]
   ```
   Expected: TRANAQTY=100, TRANEQTY=80, TRANDQTY=80

### **Test 2: Edit Existing Invoice**
1. Open existing invoice for editing
2. Net Weight field shows saved TRANEQTY value
3. Edit the quantity again
4. Save
5. **Verify:** TRANEQTY updated, TRANAQTY unchanged

### **Test 3: Amount Calculation**
1. Create invoice with edited quantity
2. **Verify calculation:**
   - Amount = Rate × TRANEQTY (not TRANAQTY)
   - GST calculated on Amount
   - Grand Total correct

---

## 🔍 SQL Verification Queries

### **Check Invoice Items:**
```sql
SELECT 
    tm.TRANDNO AS InvoiceNo,
    m.MTRLDESC AS Item,
    td.TRANAQTY AS OriginalWeight,
    td.TRANEQTY AS InvoiceWeight,
    td.TRANDQTY AS LegacyWeight,
    td.TRANDRATE AS Rate,
    td.TRANDAMT AS Amount,
    (td.TRANAQTY - td.TRANEQTY) AS Deduction
FROM TRANSACTIONDETAIL td
INNER JOIN TRANSACTIONMASTER tm ON td.TRANMID = tm.TRANMID
INNER JOIN MATERIALMASTER m ON td.MTRLID = m.MTRLID
WHERE tm.REGSTRID = 2  -- Invoices only
ORDER BY tm.TRANDATE DESC;
```

### **Find Deductions:**
```sql
-- Items where invoice weight < original weight
SELECT 
    tm.TRANDNO AS InvoiceNo,
    m.MTRLDESC AS Item,
    td.TRANAQTY AS OriginalKg,
    td.TRANEQTY AS InvoicedKg,
    (td.TRANAQTY - td.TRANEQTY) AS DeductedKg,
    CAST(((td.TRANAQTY - td.TRANEQTY) / td.TRANAQTY * 100) AS DECIMAL(5,2)) AS DeductionPercent
FROM TRANSACTIONDETAIL td
INNER JOIN TRANSACTIONMASTER tm ON td.TRANMID = tm.TRANMID
INNER JOIN MATERIALMASTER m ON td.MTRLID = m.MTRLID
WHERE tm.REGSTRID = 2 
    AND td.TRANEQTY < td.TRANAQTY
ORDER BY DeductionPercent DESC;
```

---

## ⚠️ Important Notes

### **1. Only Affects Invoices**
- Changes ONLY apply to Raw Material Invoice (REGSTRID=2)
- Raw Material Intake (REGSTRID=1) is NOT affected
- No changes to other transaction types

### **2. Frontend Already Uses NetWeight**
- Form field: **"Net Weight (kg)"**
- Frontend already sends `NetWeight` property
- No frontend changes needed!
- Backend now saves to TRANEQTY

### **3. Calculation Logic**
- Amount = Rate × **TRANEQTY** (not TRANAQTY)
- User pays for what's invoiced, not what was originally received

---

## ✅ Completion Status

| Task | Status |
|------|--------|
| Database column added | ✅ **DONE** |
| Model updated | ✅ **DONE** |
| Precision configured | ✅ **DONE** |
| GetInvoiceItems updated | ✅ **DONE** |
| GetAllInvoiceItems updated | ✅ **DONE** |
| SaveInvoice updated | ✅ **DONE** |
| INSERT statement modified | ✅ **DONE** |
| Ready to test | ✅ **YES** |

---

## 📝 Summary

**What happens now:**

1. **New Invoice:**
   - Net Weight loads from Raw Material Intake (ActualWeight = FACTORYWGT)
   - User can edit the Net Weight field
   - On save: TRANAQTY = original, TRANEQTY = edited, TRANDQTY = edited

2. **Edit Invoice:**
   - Net Weight loads from TRANEQTY
   - User can edit again
   - On save: TRANAQTY unchanged, TRANEQTY = new edited value, TRANDQTY = new edited value

3. **Database:**
   - TRANAQTY: Always preserves original from Raw Material Intake
   - TRANEQTY: Stores user's edited invoice quantity
   - TRANDQTY: Copy of TRANEQTY (for backward compatibility)

---

**TRANEQTY implementation complete! Net Weight is now fully editable in invoices while preserving original quantities.** 🎉
