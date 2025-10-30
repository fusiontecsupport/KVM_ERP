# Raw Material Invoice - Add New Form Implementation

## Summary
Successfully implemented "Add New" functionality for Raw Material Invoice with auto-fill and auto-populate features based on supplier selection.

---

## Features Implemented

### 1. **Add New Button**
- **Location**: Raw Material Invoice Index page header
- **Styling**: Red gradient button matching Raw Material Intake design
- **Action**: Navigates to Form view

### 2. **Basic Information Section**

**Fields:**
- **No**: Non-editable, placeholder shows "Auto Generated"
- **Ref No**: Text box for manual entry
- **Status**: Dropdown (Active/Inactive)
- **Supplier Name**: Dropdown with all active suppliers (Required field marked with *)

### 3. **Auto-Fill Supplier Details Section**

When a supplier is selected, these fields automatically populate (all non-editable):
- **Vehicle Number**: From `CATEGORYMASTER.CATEVNO`
- **State**: From `CATEGORYMASTER.CATESTATENAME`
- **Location**: From `CATEGORYMASTER.CATELOCATION`
- **Supplier Code**: From `CATEGORYMASTER.CATECODE`

### 4. **Auto-Populated Items Table**

When supplier is selected, items table automatically loads with data from Raw Material Intake transactions.

**Table Columns:**
1. **S.No**: Sequential number
2. **Item**: Material name (non-editable)
3. **Grade**: Grade description (non-editable)
4. **Production Colour**: Packing type description (non-editable)
5. **Received Type**: Received type description (non-editable)
6. **Actual Weight**: From intake records (non-editable)
7. **Net Weight (KG)**: Editable input field (BLANK initially)
8. **Rate (₹/KG)**: Editable input field (BLANK initially)
9. **Amount (₹)**: Auto-calculated (Net Weight × Rate) - non-editable

**Data Source**: 
- Fetches distinct items from `TRANSACTIONMASTER` and `TRANSACTIONDETAILS` tables
- Filters by selected `CATEID` (Supplier ID)
- Joins with `MATERIALMASTER`, `GRADEMASTER`, `PACKINGTYPEMASTER`, `RECEIVEDTYPEMASTER`

---

## Files Created/Modified

### 1. **Views/RawMaterialInvoice/Index.cshtml**
**Changes:**
- Added "Add New" button in header section
- Added button styling (`.add-btn` class)

### 2. **Controllers/RawMaterialInvoiceController.cs**
**Added Methods:**
- `Form()`: GET action to display the form
- `GetSupplierDetails(int supplierId)`: POST action to fetch supplier details
- `GetSupplierItems(int supplierId)`: POST action to fetch items for supplier

**Added ViewModels:**
- `SupplierItemViewModel`: For items data structure

### 3. **Views/RawMaterialInvoice/Form.cshtml** (NEW FILE)
**Sections:**
- Professional header with back button
- Basic Information form section
- Supplier Details section (auto-filled)
- Items table section (auto-populated)
- Save button
- Complete JavaScript for auto-fill and calculations

---

## How It Works

### User Flow:

1. **User clicks "Add New"** from Invoice list page
2. **Form loads** with empty fields
3. **User selects Supplier** from dropdown
4. **Auto-fill triggers:**
   - Vehicle Number populates
   - State populates
   - Location populates
   - Supplier Code populates
5. **Items table auto-populates:**
   - All items from Raw Material Intake for that supplier load
   - Item, Grade, Production Colour, Received Type, Actual Weight are pre-filled
   - Net Weight and Rate fields are blank for user input
6. **User enters Net Weight and Rate:**
   - Amount auto-calculates as: Net Weight × Rate
7. **User clicks Save:**
   - Validation checks supplier selection
   - Collects all items with Net Weight/Rate entered
   - Currently shows alert (backend save to be implemented)

---

## Technical Implementation

### JavaScript Functions:

**`loadSupplierDetails(supplierId)`**
- Makes AJAX POST to `GetSupplierDetails`
- Populates Vehicle Number, State, Location, Code fields

**`loadSupplierItems(supplierId)`**
- Makes AJAX POST to `GetSupplierItems`
- Renders items in table with `renderItemsTable()`

**`renderItemsTable()`**
- Builds HTML table rows dynamically
- Adds event listeners for Net Weight and Rate inputs
- Triggers calculation on input change

**`calculateAmount(index)`**
- Calculates: Amount = Net Weight × Rate
- Updates Amount field automatically

**`saveInvoice()`**
- Validates supplier selection
- Collects form data and items
- Prepares JSON for backend (placeholder alert currently)

### Controller Methods:

**`GetSupplierDetails(int supplierId)`**
```csharp
- Queries: CATEGORYMASTER table
- Returns: VehicleNumber, State, Location, Code
- Format: JSON with success flag
```

**`GetSupplierItems(int supplierId)`**
```csharp
- Queries: TRANSACTIONMASTER joined with:
  - TRANSACTIONDETAILS
  - MATERIALMASTER
  - GRADEMASTER
  - PACKINGTYPEMASTER
  - RECEIVEDTYPEMASTER
- Filters: By CATEID (Supplier) and DISPSTATUS
- Returns: Array of items with all fields
- Format: JSON with success flag
```

---

## Database Tables Used

### Read Operations:
1. **CATEGORYMASTER**: Supplier details
2. **TRANSACTIONMASTER**: Transaction headers
3. **TRANSACTIONDETAILS**: Transaction line items
4. **MATERIALMASTER**: Item/Material information
5. **GRADEMASTER**: Grade information
6. **PACKINGTYPEMASTER**: Production colour/packing info
7. **RECEIVEDTYPEMASTER**: Received type information

---

## Next Steps (Backend Save Implementation)

To complete the functionality, implement:

1. **SaveInvoice** action in controller:
   - Create TRANSACTIONMASTER record for invoice
   - Create TRANSACTIONDETAILS records for each item
   - Update TRANNO (invoice number) generation logic
   - Return success/error response

2. **Database Changes** (if needed):
   - Ensure invoice-specific fields exist in TRANSACTIONMASTER
   - Add any additional fields for invoice tracking

---

## Testing Steps

1. Navigate to Raw Material Invoice page
2. Click "Add New" button
3. Verify form loads with empty fields
4. Select a supplier from dropdown
5. Verify supplier details auto-fill (Vehicle, State, Location, Code)
6. Verify items table populates with supplier's items
7. Enter Net Weight for an item
8. Enter Rate for the same item
9. Verify Amount calculates automatically
10. Click Save button
11. Verify validation and data collection

---

## Design Features

- **Modern UI**: Gradient headers, rounded corners, shadows
- **Responsive**: Bootstrap grid system
- **Color Scheme**: Matching Raw Material Intake design
- **User-Friendly**: Clear sections, labeled fields, intuitive flow
- **Real-time Calculations**: Immediate feedback on Amount
- **Loading States**: Spinner shown while fetching data
- **Validation**: Required field indicators, alerts for missing data

---

## Status
✅ **COMPLETED** - All features implemented and ready for testing
⚠️ **NOTE**: Backend save functionality is placeholder (alert only) - needs full implementation

**Date**: 2025-10-29
**Developer Notes**: Form structure complete, auto-fill working, calculations functional. Backend save action needs to be implemented for persistence.
