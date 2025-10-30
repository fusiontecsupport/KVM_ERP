# Raw Material Invoice - TRANSACTIONMASTER Field Mapping

## Database Table: TRANSACTIONMASTER

### Field Mappings

| Database Field | Form Field | Source | Description |
|---------------|------------|--------|-------------|
| **TRANMID** | Auto-generated | Database Identity | Primary Key (Auto-increment) |
| **TRANDATE** | Date | Form Input | Invoice Date (Date picker) |
| **CATENAME** | Supplier Name | Supplier Master | Supplier Name from SUPPLIERMASTER |
| **CATECODE** | Supplier Code | Supplier Master | Supplier Code from SUPPLIERMASTER |
| **VECHNO** | - | Empty String | Not used for invoices (empty) |
| **DISPSTATUS** | Status | Form Dropdown | 0 = Active, 1 = Inactive |
| **CUSRID** | - | Current User | Created by user (from session) |
| **LMUSRID** | - | Current User | Last modified by user (from session) |
| **PRCSDATE** | - | DateTime.Now | Process date (auto-generated) |
| **CLIENTWGHT** | - | 0 | Not used for invoices (set to 0) |
| **COMPYID** | - | Session/Default | Company ID (from session, default: 1) |
| **REGSTRID** | - | 2 (Fixed) | Register ID (2 for Invoice, 1 for Raw Material Intake) |
| **TRANNO** | No | Auto-generated | Transaction Number (sequential per COMPYID + REGSTRID) |
| **TRANDNO** | - | Auto-generated | Document Number (formatted as "0001", "0002", etc.) |
| **TRANREFID** | Supplier Name | Form Dropdown | Supplier ID (CATEID from SUPPLIERMASTER) |
| **TRANNAMT** | - | Calculated | Total Amount (sum of all item amounts) |
| **TRANAMTWRDS** | - | NULL | Amount in words (optional, not implemented) |
| **TRANREFNO** | Ref No | Form Input | Reference Number (user input) |

## Key Business Logic

### TRANNO Generation
- **Query**: `SELECT MAX(TRANNO) FROM TRANSACTIONMASTER WHERE COMPYID = @compyId AND REGSTRID = 2`
- **Logic**: Next number = MAX(TRANNO) + 1
- **Separate Sequence**: Invoice numbers are separate from Raw Material Intake (REGSTRID = 1)

### TRANDNO Generation
- **Format**: 4-digit zero-padded number
- **Example**: TRANNO = 1 → TRANDNO = "0001"
- **Logic**: `TRANNO.ToString("D4")`

### REGSTRID Values
- **1**: Raw Material Intake
- **2**: Raw Material Invoice

### Status Values
- **0**: Active (Enabled)
- **1**: Inactive (Disabled)

## Form Fields

### Basic Information Section
1. **Date** (required) - Maps to TRANDATE
2. **No** (readonly) - Displays TRANNO / TRANDNO after save
3. **Ref No** - Maps to TRANREFNO
4. **Status** - Maps to DISPSTATUS (0=Active, 1=Inactive)

### Supplier Details Section
1. **Supplier Name** (dropdown, required) - Maps to TRANREFID, CATENAME, CATECODE
2. **Supplier Code** (readonly, auto-filled) - Display only
3. **State** (readonly, auto-filled) - Display only
4. **Location** (readonly, auto-filled) - Display only

### Items Section
- Items are loaded from Raw Material Intake (REGSTRID = 1)
- Only items from the selected supplier are shown
- User enters Net Weight and Rate
- Amount is calculated automatically (Net Weight × Rate)
- Total Amount (TRANNAMT) is sum of all item amounts

## Data Flow

1. **User selects Date** → TRANDATE
2. **User selects Supplier** → Loads CATENAME, CATECODE from SUPPLIERMASTER
3. **System loads items** → From TRANSACTIONMASTER where REGSTRID = 1 and CATECODE matches
4. **User enters Ref No** → TRANREFNO
5. **User selects Status** → DISPSTATUS
6. **User enters item details** → Calculates TRANNAMT
7. **User clicks Save** → System generates TRANNO, TRANDNO and saves to database

## Important Notes

- **REGSTRID = 2** is crucial - this separates invoices from raw material intake
- **TRANNO is sequential** per COMPYID and REGSTRID combination
- **TRANDNO is formatted** version of TRANNO (4 digits with leading zeros)
- **TRANREFID stores Supplier ID** (CATEID from SUPPLIERMASTER)
- **CATENAME and CATECODE** are denormalized for faster queries
- **Items are filtered** by REGSTRID = 1 to show only Raw Material Intake items
- **No TRANSACTIONDETAIL records** are created for invoices (only master record)

## Example Data

```sql
-- Example Invoice Record
TRANMID: 101
TRANDATE: 2025-10-30
CATENAME: 'ABC Suppliers'
CATECODE: 'SUP001'
VECHNO: ''
DISPSTATUS: 0
CUSRID: 'admin'
LMUSRID: 'admin'
PRCSDATE: 2025-10-30 13:15:00
CLIENTWGHT: 0
COMPYID: 1
REGSTRID: 2
TRANNO: 1
TRANDNO: '0001'
TRANREFID: 5
TRANNAMT: 15000.00
TRANAMTWRDS: NULL
TRANREFNO: 'INV-2025-001'
```

## Controller Methods

### SaveInvoice (POST)
- Validates supplier exists
- Gets COMPYID from session
- Generates TRANNO (sequential)
- Generates TRANDNO (formatted)
- Calculates TRANNAMT (sum of items)
- Inserts into TRANSACTIONMASTER
- Returns success with TRANMID, TRANNO, TRANDNO

### GetSupplierItems (POST)
- Filters by REGSTRID = 1 (Raw Material Intake only)
- Filters by supplier CATECODE
- Returns items with Grade, Colour, ReceivedType, ActualWeight

### Index (GET)
- Filters by REGSTRID = 2 (Invoices only)
- Orders by TRANDATE DESC, TRANNO DESC
- Displays in DataTable

## Frontend Validation

1. Date is required
2. Supplier Name is required
3. At least one item with Net Weight and Rate is required
4. All amounts are calculated automatically
5. Save button is disabled during save operation
6. Success message shows generated TRANNO and TRANDNO
7. Redirects to Index page after successful save
