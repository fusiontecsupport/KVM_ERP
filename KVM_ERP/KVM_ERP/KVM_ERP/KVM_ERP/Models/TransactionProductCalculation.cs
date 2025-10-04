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
        public int? PCK1 { get; set; }

        [Column("PCK2")]
        public int? PCK2 { get; set; }

        [Column("PCK3")]
        public int? PCK3 { get; set; }

        [Column("PCK4")]
        public int? PCK4 { get; set; }

        [Column("PCK5")]
        public int? PCK5 { get; set; }

        [Column("PCK6")]
        public int? PCK6 { get; set; }

        [Column("PCK7")]
        public int? PCK7 { get; set; }

        [Column("PCK8")]
        public int? PCK8 { get; set; }

        [Column("PCK9")]
        public int? PCK9 { get; set; }

        [Column("PCK10")]
        public int? PCK10 { get; set; }

        [Column("PCK11")]
        public int? PCK11 { get; set; }

        [Column("PCK12")]
        public int? PCK12 { get; set; }

        [Column("PCK13")]
        public int? PCK13 { get; set; }

        [Column("PCK14")]
        public int? PCK14 { get; set; }

        [Column("PCK15")]
        public int? PCK15 { get; set; }

        [Column("PCK16")]
        public int? PCK16 { get; set; }

        [Column("PCK17")]
        public int? PCK17 { get; set; }

        [Column("TOPCK")]
        public int? TOPCK { get; set; }

        [Column("PCKLVALUE")]
        public int? PCKLVALUE { get; set; }

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
    }
}
