-- Find the correct table name for Groups

SELECT 
    TABLE_NAME
FROM INFORMATION_SCHEMA.TABLES
WHERE TABLE_NAME LIKE '%Group%'
  AND TABLE_TYPE = 'BASE TABLE'
ORDER BY TABLE_NAME;

-- Common possibilities:
-- Groups
-- ApplicationGroups
-- AspNetGroups
-- Group
