# Stock View Decimal Casting Error - Fix Documentation

## Problem
Stock View was throwing error: "The cast to value type 'System.Decimal' failed because the materialized value is null."

## Root Cause
Entity Framework was generating SQL with nullable decimal Sum operations that could return NULL, but was trying to cast the result to non-nullable decimal type.

## Solution Applied

### 1. Made PackingDetailRow Properties Nullable
**File**: `Controllers/StockViewController.cs` (Lines 1055-1072)

Changed all `decimal` properties to `decimal?`:
- PCK1 through PCK17
- Total

This allows the class to handle NULL values from database properly.

### 2. Updated All Calculations to Handle Nullables
**File**: `Controllers/StockViewController.cs`

Added null coalescing operator `?? 0` to:
- upToPreviousData.Total calculation (Line 409)
- selectedDayData.Total calculation (Line 438)
- totalData PCK additions (Lines 449-466)
- noOfBoxesData.Total calculation (Line 493)

### 3. Updated CalculateBoxes Method
**File**: `Controllers/StockViewController.cs` (Line 93)

Changed parameter from `decimal` to `decimal?`:
```csharp
private decimal CalculateBoxes(decimal? totalValue)
{
    decimal boxes = (totalValue ?? 0) / 6;
    // ...
}
```

### 4. Fixed LINQ Queries - Load to Memory First
**File**: `Controllers/StockViewController.cs` (Lines 915-977)

**Key Change**: Instead of performing complex Sum operations in SQL via Entity Framework, we now:
1. Load raw data into memory with `.ToList()`
2. Perform grouping and summing in .NET code (client-side)

**Before** (problematic):
```csharp
var productCalcs = (from tpc in db.TransactionProductCalculations
                   // ... joins and where clause
                   group tpc by new { m.MTRLID, m.MTRLDESC } into g
                   select new {
                       ProductId = g.Key.MTRLID,
                       ProductName = g.Key.MTRLDESC,
                       TotalPCK = g.Sum(tpc => (tpc.PCK1 ?? 0) + ...) // EF translation issue
                   }).ToList();
```

**After** (fixed):
```csharp
// Step 1: Load all individual records into memory
var allCalcs = (from tpc in db.TransactionProductCalculations
               // ... joins and where clause
               select new {
                   ProductId = m.MTRLID,
                   ProductName = m.MTRLDESC,
                   PCK1 = tpc.PCK1,
                   PCK2 = tpc.PCK2,
                   // ... all PCK fields
               }).ToList();

// Step 2: Group and sum in .NET (client-side)
var productCalcs = allCalcs
    .GroupBy(x => new { x.ProductId, x.ProductName })
    .Select(g => new {
        ProductId = g.Key.ProductId,
        ProductName = g.Key.ProductName,
        TotalPCK = g.Sum(tpc => (tpc.PCK1 ?? 0) + (tpc.PCK2 ?? 0) + ...)
    })
    .Where(x => x.TotalPCK > 0)
    .ToList();
```

### 5. Fixed BKN Query Similarly
**File**: `Controllers/StockViewController.cs` (Lines 980-989)

**Before**:
```csharp
var bknTotal = ((from tpc in db.TransactionProductCalculations
               // ...
               select (decimal?)tpc.BKN).Sum() ?? 0);
```

**After**:
```csharp
var bknData = (from tpc in db.TransactionProductCalculations
              // ...
              select tpc.BKN).ToList();

var bknTotal = bknData.Sum(x => x ?? 0);
```

## Benefits of This Approach

1. **Eliminates EF Translation Issues**: No more complex nullable decimal operations in SQL
2. **Better Performance Control**: We control exactly what data is loaded from database
3. **Cleaner .NET Code**: Summing and grouping in .NET is straightforward
4. **No Casting Errors**: .NET handles nullable decimals perfectly

## Testing Steps

1. Build the project in Visual Studio
2. Navigate to Stock View page
3. Select a date and click Filter
4. Verify products display with totals
5. Click + button to expand details
6. Verify detailed breakdown shows correctly

## Files Modified

- `Controllers/StockViewController.cs`
  - Lines 93-99: CalculateBoxes method
  - Lines 409-414: upToPreviousData.Total calculation
  - Lines 438-443: selectedDayData.Total calculation
  - Lines 446-467: totalData calculations
  - Lines 493-498: noOfBoxesData.Total calculation
  - Lines 915-977: Product totals query
  - Lines 980-989: BKN totals query
  - Lines 1055-1072: PackingDetailRow class

## Date
2025-10-29

## Status
✅ FIXED - Stock View should now load without decimal casting errors
