# Connect to the hardware server
connect

# Reset the entire system
targets -set -nocase -filter {name =~ "*APU*"}
rst -system
after 1000

# Program the FPGA bitstream
puts "Programming FPGA bitstream..."
fpga "C:/Users/hp/Downloads/Internship/Extended/AES256/platform/hw/design_1_wrapper.bit"
after 1000

# Source the PS7 initialization script
puts "Initializing Processing System (PS)..."
source "C:/Users/hp/Downloads/Internship/Extended/AES256/platform/hw/ps7_init.tcl"
targets -set -nocase -filter {name =~ "*Cortex-A9 MPCore #0*"}
ps7_init
ps7_post_config
after 500

# Download the compiled application ELF
puts "Downloading application ELF..."
dow "C:/Users/hp/Downloads/Internship/Extended/AES256/app_component/build/app_component.elf"

# Resume processor execution
puts "Running application on Cortex-A9 Core 0..."
con
disconnect
puts "Programming complete. The board is now running the AES server."
