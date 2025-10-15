using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace KVM_ERP.Models
{
    [Table("TRANSACTION_PRODUCT_CALCULATION")]
    public class TransactionProductCalculation
    {
        [Key]
        [Column("TRANPID")]
        public int TRANPID { get; set; }

        [Required]
        [Column("TRANMID")]
        public int TRANMID { get; set; }

        [Required]
        [Column("TRANDID")]
        public int TRANDID { get; set; }

        [Required]
        [Column("PACKMID")]
        public int PACKMID { get; set; }

        [Column("PCK1")]
        public decimal? PCK1 { get; set; }

        [Column("PCK2")]
        public decimal? PCK2 { get; set; }

        [Column("PCK3")]
        public decimal? PCK3 { get; set; }

        [Column("PCK4")]
        public decimal? PCK4 { get; set; }

        [Column("PCK5")]
        public decimal? PCK5 { get; set; }

        [Column("PCK6")]
        public decimal? PCK6 { get; set; }

        [Column("PCK7")]
        public decimal? PCK7 { get; set; }

        [Column("PCK8")]
        public decimal? PCK8 { get; set; }

        [Column("PCK9")]
        public decimal? PCK9 { get; set; }

        [Column("PCK10")]
        public decimal? PCK10 { get; set; }

        [Column("PCK11")]
        public decimal? PCK11 { get; set; }

        [Column("PCK12")]
        public decimal? PCK12 { get; set; }

        [Column("PCK13")]
        public decimal? PCK13 { get; set; }

        [Column("PCK14")]
        public decimal? PCK14 { get; set; }

        [Column("PCK15")]
        public decimal? PCK15 { get; set; }

        [Column("PCK16")]
        public decimal? PCK16 { get; set; }

        [Column("PCK17")]
        public decimal? PCK17 { get; set; }

        [Column("TOPCK")]
        public decimal? TOPCK { get; set; }

        [Column("PCKLVALUE")]
        public decimal? PCKLVALUE { get; set; }

        [Column("AVGPCKVALUE")]
        public decimal? AVGPCKVALUE { get; set; }

        [Column("PNDSVALUE")]
        public decimal? PNDSVALUE { get; set; }

        [Column("TOTALPNDS")]
        public decimal? TOTALPNDS { get; set; }

        [Column("YELDPERCENT")]
        public decimal? YELDPERCENT { get; set; }

        [Column("TOTALYELDCOUNTS")]
        public decimal? TOTALYELDCOUNTS { get; set; }

        [Column("KGWGT")]
        public decimal? KGWGT { get; set; }

        [Column("PCKKGWGT")]
        public decimal? PCKKGWGT { get; set; }

        [Column("WASTEWGT")]
        public decimal? WASTEWGT { get; set; }

        [Column("WASTEPWGT")]
        public decimal? WASTEPWGT { get; set; }

        [Column("FACTORYWGT")]
        public decimal? FACTORYWGT { get; set; }

        [Column("FACAVGWGT")]
        public decimal? FACAVGWGT { get; set; }

        [Column("FACAVGCOUNT")]
        public decimal? FACAVGCOUNT { get; set; }

        [Column("DISPSTATUS")]
        public short? DISPSTATUS { get; set; }

        [MaxLength(100)]
        [Column("CUSRID")]
        public string CUSRID { get; set; }

        [MaxLength(100)]
        [Column("LMUSRID")]
        public string LMUSRID { get; set; }

        [Column("PRCSDATE")]
        public DateTime? PRCSDATE { get; set; }

        [Column("PRODDATE")]
        public DateTime? PRODDATE { get; set; }

        [Column("CALCULATIONMODE")]
        public int? CALCULATIONMODE { get; set; }

        // [Column("CLIENTWGHT")]
        // public int? CLIENTWGHT { get; set; }  // Removed - column doesn't exist in database
    }
}
