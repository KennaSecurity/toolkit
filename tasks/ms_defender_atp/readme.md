## Running Microsoft Defender ATP task 

To run this task you need the following information from Microsoft: 

1. Tenant ID
1. Client ID
1. Client Secret

Start here to learn how to register your app:

>>https://docs.microsoft.com/en-us/azure/active-directory/develop/scenario-web-api-call-api-app-registration

>>https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-modify-supported-accounts


Work is done here: https://portal.azure.com/

1. Create APP
1. Generate Secret - **BE SURE TO SAVE IT SOMEWHERE SAFE - YOU WON’T BE ABLE GET IT FROM THE UI AGAIN**
1. Use App Permissions to set access rights for the Application to the MS Defenders ATP API. 
1. View the app Information page to see the Tenant/Directory ID and the Client/Application ID. 


## Command Line

See the main Toolkit for instrustions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specifed output directory. You can review the file before attempting to upload to the Kenna directly. 

Recommended Steps: 

1. Run with Microsoft Keys only to ensure you are able to get data properly from Defender ATP
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: MS Defender Atp KDI) 
1, Manually run the connector with the json from step 1 
1. Click on the name of the connector to get the connector id
1. Run the task with Microsoft Keys and Kenna Key/connector id


Complete list of Options:

options: [
        { :name => "atp_tenant_id", 
          :type => "string", 
          :required => true, 
          :default => nil, 
          :description => "MS Defender ATP Tenant ID" },
        { :name => "atp_client_id", 
          :type => "api_key", 
          :required => true, 
          :default => nil, 
          :description => "MS Defender ATP Client ID" },
        { :name => "atp_client_secret", 
          :type => "api_key", 
          :required => true, 
          :default => nil, 
          :description => "MS Defender ATP Client Secret" },
        { :name => "atp_api_host", 
          :type => "hostname", 
          :required => false, 
          :default => "https://api.securitycenter.microsoft.com", 
          :description => "url to retrieve Defender hosts and vulns"},
        { :name => "atp_oath_host", 
          :type => "hostname", 
          :required => false, 
          :default => "https://login.windows.net", 
          :description => "url for Defender authentication"},        
        { :name => "kenna_api_key", 
          :type => "api_key", 
          :required => false, 
          :default => nil, 
          :description => "Kenna API Key for use with connector option"},
        { :name => "kenna_api_host", 
          :type => "hostname", 
          :required => false, 
          :default => "api.kennasecurity.com", 
          :description => "Kenna API Hostname if not US shared" }, 
        { :name => "kenna_connector_id", 
          :type => "integer", 
          :required => false, 
          :default => nil, 
          :description => "If set, we'll try to upload to this connector"  },    
        { :name => "output_directory", 
          :type => "filename", 
          :required => false, 
          :default => "output/microsoft_atp", 
          :description => "If set, will write a file upon completion. Path is relative to #{$basedir}"  }
      ]
