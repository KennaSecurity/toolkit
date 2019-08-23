# upload_assets

Adds new assets to Kenna

If you don't want to make any changes to the code, use the following column names in your csv file, 
order doesn't matter except the first column should be ip_address:

    ip_address
    hostname
    url
    mac_address
    netbios
    fqdn
    file
    application

Required Ruby classes/gems:

    rest-client
    json
    csv

Usage: add_assets.rb applicationkey primarylocator csvfilelocation (optional_csv_headerfile)

Rows missing data for the Primary Locator will fail and give an error message. 
