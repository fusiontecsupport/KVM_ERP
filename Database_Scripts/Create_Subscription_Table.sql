USE [KVM_ERP]
GO

/****** Object:  Table [dbo].[Subscription]    Script Date: 10-10-2025 14:57:34 ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

-- Check if table exists and drop if it does (for development purposes)
IF EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[Subscription]') AND type in (N'U'))
DROP TABLE [dbo].[Subscription]
GO

CREATE TABLE [dbo].[Subscription](
	[SubscriptionId] [int] IDENTITY(1,1) NOT NULL,
	[UserId] [nvarchar](128) NOT NULL,
	[PlanName] [nvarchar](50) NOT NULL,
	[StartDate] [datetime] NOT NULL,
	[ExpiryDate] [datetime] NOT NULL,
	[IsActive] [bit] NOT NULL,
	[CreatedAt] [datetime] NOT NULL,
	[UpdatedAt] [datetime] NULL,
PRIMARY KEY CLUSTERED 
(
	[SubscriptionId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO

-- Add default constraints
ALTER TABLE [dbo].[Subscription] ADD  DEFAULT ((1)) FOR [IsActive]
GO

ALTER TABLE [dbo].[Subscription] ADD  DEFAULT (getdate()) FOR [CreatedAt]
GO

-- Add foreign key constraint to AspNetUsers table
ALTER TABLE [dbo].[Subscription]  WITH CHECK ADD CONSTRAINT [FK_Subscription_AspNetUsers] FOREIGN KEY([UserId])
REFERENCES [dbo].[AspNetUsers] ([Id])
ON DELETE CASCADE
GO

ALTER TABLE [dbo].[Subscription] CHECK CONSTRAINT [FK_Subscription_AspNetUsers]
GO

-- Create index for better performance on UserId lookups
CREATE NONCLUSTERED INDEX [IX_Subscription_UserId] ON [dbo].[Subscription]
(
	[UserId] ASC
)
INCLUDE ([IsActive], [ExpiryDate])
GO

-- Create index for subscription expiry checks
CREATE NONCLUSTERED INDEX [IX_Subscription_ExpiryDate] ON [dbo].[Subscription]
(
	[ExpiryDate] ASC,
	[IsActive] ASC
)
GO

PRINT 'Subscription table created successfully with indexes and constraints.'
