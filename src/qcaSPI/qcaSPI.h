
// Pin definitions
#define PIN_QCA700X_INT 21             // SPI connections to QCA7000X
#define PIN_QCA700X_CS 5
#define SPI_MOSI 23
#define SPI_MISO 19
#define SPI_SCK 18

/* SPI registers QCA700X */

#define QCA7K_SPI_READ (1 << 15)                // MSB(15) of each command (16 bits) is the read(1) or write(0) bit.
#define QCA7K_SPI_WRITE (0 << 15)
#define QCA7K_SPI_INTERNAL (1 << 14)            // MSB(14) sets the Internal Registers(1) or Data Buffer(0)
#define QCA7K_SPI_EXTERNAL (0 << 14)

#define	SPI_REG_BFR_SIZE        0x0100
#define SPI_REG_WRBUF_SPC_AVA   0x0200
#define SPI_REG_RDBUF_BYTE_AVA  0x0300
#define SPI_REG_SPI_CONFIG      0x0400
#define SPI_REG_INTR_CAUSE      0x0C00
#define SPI_REG_INTR_ENABLE     0x0D00
#define SPI_REG_RDBUF_WATERMARK 0x1200
#define SPI_REG_WRBUF_WATERMARK 0x1300
#define SPI_REG_SIGNATURE       0x1A00
#define SPI_REG_ACTION_CTRL     0x1B00

#define QCASPI_GOOD_SIGNATURE   0xAA55
#define QCA7K_BUFFER_SIZE       3163

#define SPI_INT_WRBUF_BELOW_WM (1 << 10)
#define SPI_INT_CPU_ON         (1 << 6)
#define SPI_INT_ADDR_ERR       (1 << 3)
#define SPI_INT_WRBUF_ERR      (1 << 2)
#define SPI_INT_RDBUF_ERR      (1 << 1)
#define SPI_INT_PKT_AVLBL      (1 << 0)


uint16_t qcaspi_read_register16(uint16_t reg);

void qcaspi_write_register(uint16_t reg, uint16_t value);

void qcaspi_write_burst(uint8_t *src, uint32_t len);

uint32_t qcaspi_read_burst(uint8_t *dst);