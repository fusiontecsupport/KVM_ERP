# PurchaseInvoiceStatus Model - Added

## 📝 New Table Model Created

Added Entity Framework model for the `PURCHASEINVOICESTATUS` database table.

---

## 🆕 Files Created/Modified

### **1. New Model File Created:**
**`Models/PurchaseInvoiceStatus.cs`**

```csharp
[Table("PURCHASEINVOICESTATUS")]
public class PurchaseInvoiceStatus
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int PUINSTID { get; set; }

    [DisplayName("Status Description")]
    [Required(ErrorMessage = "Please enter status description")]
    [MaxLength(50)]
    public string PUINSTDESC { get; set; }

    [DisplayName("Status Code")]
    [MaxLength(15)]
    public string PUINSTCODE { get; set; }

    [MaxLength(100)]
    public string CUSRID { get; set; }

    [MaxLength(100)]
    public string LMUSRID { get; set; }

    [DisplayName("Status")]
    public short? DISPSTATUS { get; set; } = 0;

    [DisplayName("Process Date")]
    [DataType(DataType.DateTime)]
    public DateTime? PRCSDATE { get; set; }
}
```

### **2. Modified File:**
**`Models/ApplicationDbContext.cs`**

Added DbSet property:
```csharp
public DbSet<PurchaseInvoiceStatus> PurchaseInvoiceStatuses { get; set; }
```

---

## 📊 Table Structure

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| PUINSTID | int | No | IDENTITY(1,1) | Primary Key |
| PUINSTDESC | varchar(50) | Yes | NULL | Status Description |
| PUINSTCODE | varchar(15) | Yes | NULL | Status Code |
| CUSRID | varchar(100) | Yes | NULL | Created User ID |
| LMUSRID | varchar(100) | Yes | NULL | Last Modified User ID |
| DISPSTATUS | smallint | Yes | 0 | Display Status |
| PRCSDATE | datetime | Yes | NULL | Process Date |

---

## 🎯 Model Features

**Attributes Used:**
- ✅ `[Table("PURCHASEINVOICESTATUS")]` - Maps to database table
- ✅ `[Key]` - Defines primary key
- ✅ `[DatabaseGenerated(DatabaseGeneratedOption.Identity)]` - Auto-increment
- ✅ `[DisplayName]` - User-friendly labels for UI
- ✅ `[Required]` - Validation for required fields
- ✅ `[MaxLength]` - String length validation
- ✅ `[DataType]` - Data type specification

**Default Values:**
- `DISPSTATUS` defaults to `0`
- `PUINSTDESC` is required
- All other fields are nullable

---

## 💡 Usage Examples

### **1. Query All Statuses**
```csharp
using (var db = new ApplicationDbContext())
{
    var statuses = db.PurchaseInvoiceStatuses
        .Where(p => p.DISPSTATUS == 0)
        .OrderBy(p => p.PUINSTDESC)
        .ToList();
}
```

### **2. Create New Status**
```csharp
using (var db = new ApplicationDbContext())
{
    var newStatus = new PurchaseInvoiceStatus
    {
        PUINSTDESC = "Pending Approval",
        PUINSTCODE = "PA01",
        CUSRID = User.Identity.Name,
        DISPSTATUS = 0,
        PRCSDATE = DateTime.Now
    };
    
    db.PurchaseInvoiceStatuses.Add(newStatus);
    db.SaveChanges();
}
```

### **3. Update Status**
```csharp
using (var db = new ApplicationDbContext())
{
    var status = db.PurchaseInvoiceStatuses.Find(id);
    if (status != null)
    {
        status.PUINSTDESC = "Updated Description";
        status.LMUSRID = User.Identity.Name;
        status.PRCSDATE = DateTime.Now;
        db.SaveChanges();
    }
}
```

### **4. Dropdown Binding**
```csharp
// In Controller
ViewBag.StatusList = db.PurchaseInvoiceStatuses
    .Where(s => s.DISPSTATUS == 0)
    .Select(s => new SelectListItem 
    { 
        Value = s.PUINSTID.ToString(), 
        Text = s.PUINSTDESC 
    })
    .ToList();

// In View
@Html.DropDownList("StatusId", (IEnumerable<SelectListItem>)ViewBag.StatusList, 
    "-- Select Status --", new { @class = "form-control" })
```

---

## 🚀 Next Steps

### **If you want to create a full CRUD for this master:**

1. **Create Controller:**
   - `Controllers/Masters/PurchaseInvoiceStatusController.cs`
   - Actions: Index, Create, Edit, Delete

2. **Create Views:**
   - `Views/PurchaseInvoiceStatus/Index.cshtml`
   - `Views/PurchaseInvoiceStatus/Form.cshtml`

3. **Add Menu Item:**
   - Add to Masters menu in `_navbar.cshtml`
   - Create role: `PurchaseInvoiceStatusIndex`, `PurchaseInvoiceStatusCreate`, etc.

4. **Add Validation:**
   - Remote validation for duplicate codes
   - Client-side validation

---

## ✅ Status

| Task | Status |
|------|--------|
| Model class created | ✅ **DONE** |
| Added to ApplicationDbContext | ✅ **DONE** |
| Mapped to database table | ✅ **DONE** |
| Attributes configured | ✅ **DONE** |
| Ready to use | ✅ **YES** |

---

## 📝 Notes

- The model is now ready to be used in controllers and views
- Build the solution to ensure no compilation errors
- The table already exists in the database, so no migration is needed
- You can now query, insert, update, and delete records using Entity Framework

---

**PurchaseInvoiceStatus model successfully added to the project!** 🎉
