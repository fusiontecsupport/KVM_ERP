# Invoice Approval Mode - Advanced Implementation

## 📝 Overview

Implemented advanced approval workflow features for Invoice Approval page:
1. Shows only "Approved" and "Cancel" status options
2. Saves net weight changes only to TRANDQTY (preserves TRANAQTY and TRANEQTY)
3. Hides approved invoices from Invoice Approval page
4. Disables edit button for approved invoices

---

## ✅ Features Implemented

### **1. Dynamic Status Dropdown** ✅
- **Regular Invoice Mode:** Shows "Cancel" and "Waiting for Approval"
- **Approval Mode:** Shows "Approved" and "Cancel"

### **2. Three-Way Quantity Management** ✅
- **TRANAQTY:** Original quantity (always preserved)
- **TRANEQTY:** First edited quantity (preserved in approval mode)
- **TRANDQTY:** Latest quantity (updated in approval mode)

### **3. Smart Edit Button** ✅
- Shows edit button only for "Waiting for Approval" status
- Approved invoices show only Print button

### **4. Auto-Filtering** ✅
- Invoice Approval page shows only "Waiting for Approval"
- Approved invoices automatically removed from list

---

## 🔄 Data Flow

### **Scenario: Invoice Approval Workflow**

**Step 1: Initial Invoice Creation**
```
User creates invoice in Regular Invoice page:
- TRANAQTY = 100 (from Raw Material Intake)
- TRANEQTY = 100 (Net Weight entered)
- TRANDQTY = 100 (Same as TRANEQTY)
- Status = "Waiting for Approval"
```

**Step 2: First Approval Edit**
```
Approver edits in Invoice Approval page:
- Changes Net Weight from 100 → 80
- Status still "Waiting for Approval"

On Save:
- TRANAQTY = 100 (preserved)
- TRANEQTY = 100 (preserved)
- TRANDQTY = 80  (updated with new value)
```

**Step 3: Second Approval Edit**
```
Approver edits again:
- Changes Net Weight from 80 → 85
- Status still "Waiting for Approval"

On Save:
- TRANAQTY = 100 (preserved)
- TRANEQTY = 100 (preserved from first save)
- TRANDQTY = 85  (updated with latest value)
```

**Step 4: Final Approval**
```
Approver changes status to "Approved"

Result:
- TRANAQTY = 100
- TRANEQTY = 100  
- TRANDQTY = 85
- Status = "Approved"
- Invoice disappears from Invoice Approval page
- Edit button disabled (read-only mode)
```

---

## 🎯 Controller Changes

### **RawMaterialInvoiceController.cs**

#### **1. Form Action Updated:**
```csharp
public ActionResult Form(int? id, string source = null)
{
    bool isApprovalMode = source == "approval";
    ViewBag.IsApprovalMode = isApprovalMode;
    
    if (isApprovalMode)
    {
        // Show "Approved" and "Cancel"
        ViewBag.InvoiceStatuses = context.PurchaseInvoiceStatuses
            .Where(s => (s.DISPSTATUS == 0 || s.DISPSTATUS == null) && 
                   (s.PUINSTCODE == "PUS001" || s.PUINSTCODE == "PUS002"))
            .ToList();
    }
    else
    {
        // Show "Cancel" and "Waiting for Approval"
        ViewBag.InvoiceStatuses = context.PurchaseInvoiceStatuses
            .Where(s => (s.DISPSTATUS == 0 || s.DISPSTATUS == null) && 
                   (s.PUINSTCODE == "PUS002" || s.PUINSTCODE == "PUS003"))
            .ToList();
    }
}
```

#### **2. SaveInvoice Action Updated:**
```csharp
// Before deleting items, save existing quantities
if (model.IsApprovalMode)
{
    existingQuantities = new Dictionary<int, Tuple<decimal, decimal>>();
    var existingItems = context.Database.SqlQuery<ExistingItemQuantities>(@"
        SELECT TRANDAID, TRANAQTY, TRANEQTY 
        FROM TRANSACTIONDETAIL 
        WHERE TRANMID = @p0
    ", tranMId).ToList();
    
    foreach (var item in existingItems)
    {
        existingQuantities[item.TRANDAID] = Tuple.Create(item.TRANAQTY, item.TRANEQTY);
    }
}

// When inserting items
if (model.IsApprovalMode && existingQuantities != null && existingQuantities.ContainsKey(trandaid))
{
    // Approval Mode: Keep original TRANAQTY and TRANEQTY, only update TRANDQTY
    tranaqty = existingQuantities[trandaid].Item1;  // Original TRANAQTY
    traneqty = existingQuantities[trandaid].Item2;  // Previous TRANEQTY
    trandqty = item.NetWeight;                       // New value goes to TRANDQTY
}
else
{
    // Regular Mode: NetWeight goes to both TRANEQTY and TRANDQTY
    tranaqty = item.ActualWeight;
    traneqty = item.NetWeight;
    trandqty = item.NetWeight;
}
```

---

## 🎨 View Changes

### **PurchaseInvoiceApproval/Index.cshtml**

#### **Smart Edit Button:**
```javascript
render: function(data, type, row) {
    var buttons = '';
    // Only show Edit button for "Waiting for Approval" status
    if (row.StatusDescription === 'Waiting for Approval') {
        buttons += '<a href="@Url.Action("Form", "RawMaterialInvoice")?id=' + row.TRANMID + '&source=approval" ...>';
    }
    // Always show Print button
    buttons += '<button onclick="printInvoice(' + row.TRANMID + ')" ...>';
    return buttons;
}
```

### **RawMaterialInvoice/Form.cshtml**

#### **IsApprovalMode Flag:**
```javascript
var invoiceData = {
    InvoiceId: @(ViewBag.EditId ?? 0),
    InvoiceDate: $('#invoiceDate').val(),
    // ... other fields
    IsApprovalMode: @(ViewBag.IsApprovalMode != null && ViewBag.IsApprovalMode ? "true" : "false")
};
```

#### **Smart Redirect:**
```csharp
@if (ViewBag.IsApprovalMode != null && ViewBag.IsApprovalMode) {
    @:window.location.href = '@Url.Action("Index", "PurchaseInvoiceApproval")';
} else {
    @:window.location.href = '@Url.Action("Index", "RawMaterialInvoice")';
}
```

---

## 📊 Database Schema

### **Status Codes:**

| Code | Description | Used In |
|------|-------------|---------|
| **PUS001** | Approved | Approval Mode |
| **PUS002** | Cancel | Both Modes |
| **PUS003** | Waiting for Approval | Regular Mode |

### **Quantity Columns:**

| Column | Purpose | Updated By |
|--------|---------|------------|
| **TRANAQTY** | Original quantity from Raw Material Intake | Never changes |
| **TRANEQTY** | First edited quantity (from regular invoice) | Regular Mode only |
| **TRANDQTY** | Latest quantity (for approval adjustments) | Both Modes |

---

## 🔍 Example Scenarios

### **Scenario 1: Normal Approval**
```
1. Create Invoice:
   TRANAQTY=100, TRANEQTY=100, TRANDQTY=100, Status=Waiting

2. Approve (no changes):
   TRANAQTY=100, TRANEQTY=100, TRANDQTY=100, Status=Approved
   → Invoice disappears from Approval page
   → Edit button disabled
```

### **Scenario 2: Approval with Adjustment**
```
1. Create Invoice:
   TRANAQTY=100, TRANEQTY=100, TRANDQTY=100, Status=Waiting

2. Edit in Approval (change to 85):
   TRANAQTY=100, TRANEQTY=100, TRANDQTY=85, Status=Waiting
   → Still in Approval page
   → Edit button still visible

3. Approve:
   TRANAQTY=100, TRANEQTY=100, TRANDQTY=85, Status=Approved
   → Invoice disappears from Approval page
   → Edit button disabled
```

### **Scenario 3: Multiple Adjustments**
```
1. Create Invoice:
   TRANAQTY=100, TRANEQTY=100, TRANDQTY=100, Status=Waiting

2. First Edit (change to 80):
   TRANAQTY=100, TRANEQTY=100, TRANDQTY=80, Status=Waiting

3. Second Edit (change to 85):
   TRANAQTY=100, TRANEQTY=100, TRANDQTY=85, Status=Waiting

4. Third Edit (change to 82):
   TRANAQTY=100, TRANEQTY=100, TRANDQTY=82, Status=Waiting

5. Approve:
   TRANAQTY=100, TRANEQTY=100, TRANDQTY=82, Status=Approved
```

---

## 📁 Files Modified

| File | Change Description |
|------|-------------------|
| `Controllers/RawMaterialInvoiceController.cs` | Added source parameter, approval mode logic |
| `Views/RawMaterialInvoice/Form.cshtml` | Added IsApprovalMode flag, smart redirect |
| `Views/PurchaseInvoiceApproval/Index.cshtml` | Smart edit button visibility |

---

## 🚀 Testing Steps

### **Test 1: Status Dropdown**
1. Open invoice from **Regular Invoice** page
2. **Verify:** Status dropdown shows "Cancel" and "Waiting for Approval"
3. Open same invoice from **Invoice Approval** page (add `&source=approval`)
4. **Verify:** Status dropdown shows "Approved" and "Cancel"

### **Test 2: Quantity Preservation**
1. Create invoice with NetWeight = 100
2. **Check DB:** TRANAQTY=100, TRANEQTY=100, TRANDQTY=100
3. Edit from Approval page, change to 80
4. **Check DB:** TRANAQTY=100, TRANEQTY=100, TRANDQTY=80
5. Edit again, change to 85
6. **Check DB:** TRANAQTY=100, TRANEQTY=100, TRANDQTY=85

### **Test 3: Auto-Filtering**
1. Create invoice with Status="Waiting for Approval"
2. **Verify:** Invoice appears in Invoice Approval page
3. Edit invoice, change Status to "Approved"
4. **Verify:** Invoice disappears from Invoice Approval page
5. **Verify:** Invoice still visible in regular Invoice page

### **Test 4: Edit Button**
1. Go to Invoice Approval page
2. **Verify:** "Waiting for Approval" invoices have Edit button
3. Edit invoice, approve it
4. Return to Invoice Approval page (if any remain)
5. **Verify:** Approved invoices (if any) have no Edit button

---

## 💡 SQL Verification Queries

### **Check Quantity Values:**
```sql
SELECT 
    tm.TRANDNO AS InvoiceNo,
    pis.PUINSTDESC AS Status,
    td.TRANAQTY AS OriginalQty,
    td.TRANEQTY AS FirstEditQty,
    td.TRANDQTY AS LatestQty,
    m.MTRLDESC AS Item
FROM TRANSACTIONDETAIL td
INNER JOIN TRANSACTIONMASTER tm ON td.TRANMID = tm.TRANMID
INNER JOIN MATERIALMASTER m ON td.MTRLID = m.MTRLID
LEFT JOIN PURCHASEINVOICESTATUS pis ON tm.DISPSTATUS = pis.PUINSTID
WHERE tm.REGSTRID = 2
ORDER BY tm.TRANDATE DESC;
```

### **Find Invoices Pending Approval:**
```sql
SELECT 
    tm.TRANDNO,
    tm.TRANDATE,
    tm.CATENAME AS Supplier,
    pis.PUINSTDESC AS Status
FROM TRANSACTIONMASTER tm
LEFT JOIN PURCHASEINVOICESTATUS pis ON tm.DISPSTATUS = pis.PUINSTID
WHERE tm.REGSTRID = 2 
AND pis.PUINSTCODE = 'PUS003'
ORDER BY tm.TRANDATE DESC;
```

### **Track Quantity Changes:**
```sql
SELECT 
    tm.TRANDNO,
    m.MTRLDESC,
    td.TRANAQTY,
    td.TRANEQTY,
    td.TRANDQTY,
    (td.TRANAQTY - td.TRANDQTY) AS TotalDeduction,
    pis.PUINSTDESC AS Status
FROM TRANSACTIONDETAIL td
INNER JOIN TRANSACTIONMASTER tm ON td.TRANMID = tm.TRANMID
INNER JOIN MATERIALMASTER m ON td.MTRLID = m.MTRLID
LEFT JOIN PURCHASEINVOICESTATUS pis ON tm.DISPSTATUS = pis.PUINSTID
WHERE tm.REGSTRID = 2
AND td.TRANDQTY < td.TRANAQTY  -- Show only adjusted items
ORDER BY tm.TRANDATE DESC;
```

---

## ⚠️ Important Notes

### **1. Quantity Logic**
- **Regular Mode:** Both TRANEQTY and TRANDQTY are updated together
- **Approval Mode:** Only TRANDQTY is updated, TRANAQTY and TRANEQTY preserved

### **2. Status Filtering**
- Invoice Approval page filters by `PUINSTCODE = 'PUS003'`
- Once approved (`PUS001`), invoice automatically hidden

### **3. Edit Button Logic**
- JavaScript checks `row.StatusDescription === 'Waiting for Approval'`
- Approved invoices have no edit button

### **4. Redirect Behavior**
- From Approval page → saves → returns to Approval page
- From Regular page → saves → returns to Regular page

---

## ✅ Completion Checklist

- [x] Controller updated with source parameter
- [x] Dynamic status dropdown based on mode
- [x] Save logic preserves TRANAQTY and TRANEQTY
- [x] TRANDQTY updated in approval mode
- [x] Edit button hidden for approved invoices
- [x] Smart redirect after save
- [x] ExistingItemQuantities model added
- [x] Dictionary stores existing quantities
- [x] No changes to regular invoice functionality

---

## 📝 Summary

**Approval Mode successfully implemented with advanced features:**

### **Key Highlights:**
- ✅ **Smart Status Options:** Different dropdowns for different modes
- ✅ **Three-Way Quantities:** TRANAQTY, TRANEQTY, TRANDQTY tracked separately
- ✅ **Data Preservation:** Original and first-edit quantities never lost
- ✅ **Auto-Filtering:** Approved invoices disappear from approval list
- ✅ **Conditional UI:** Edit button shows only when editable
- ✅ **Context-Aware:** Form knows if it's in approval mode
- ✅ **Smart Navigation:** Returns to correct page after save

### **Workflow:**
1. Create invoice → Status: "Waiting for Approval"
2. Appears in Invoice Approval page
3. Edit button visible
4. Can adjust quantity → saves to TRANDQTY only
5. Change status to "Approved"
6. Invoice disappears from Approval page
7. Edit button no longer visible (if any approved invoices shown)

**Invoice Approval workflow is complete with quantity tracking and smart UI!** 🎉
