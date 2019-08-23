module Kenna 
module Toolkit
class UserRoleSync < Kenna::Toolkit::BaseTask

def metadata 
	{
		id: "user_role_sync",
		name: "User Role Sync",
		description: "This task does blah blah blah (TODO)",
		options: [
			{:name => "kenna_api_token", 
				:type => "api_token", 
				:required => true, 
				:default => nil, 
				:description => "Kenna API Key" },
			{:name => "kenna_api_host", 
				:type => "hostname", 
				:required => false, 
				:default => "api.kennasecurity.com", 
				:description => "Kenna API Hostname" },
			{:name => "csv_file", 
				:type => "filename", 
				:required => true, 
				:default => "tasks/user_role_sync/users.csv", 
				:description => "Path to CSV file with user and role information, relative to #{$basedir}"  },
			{:name => "email_column", 
				:type => "string", 
				:required => false, 
				:default => "EmailAddress", 
				:description => "Header for the CSV file column containing an email address"  },
			{:name => "firstname_column", 
				:type => "string", 
				:required => false, 
				:default => "FirstName",
				:description => "Header for the CSV file column containing a first name" },
			{:name => "lastname_column", 
				:type => "string",
				:required => false, 
				:default => "Lastname",
				:description => "Header for the CSV file column containing a last name" },
			{:name => "role_column", 
				:type => "string", 
				:required => false, 
				:default => "ADGroup", 
				:description => "Header for the CSV file column containing a role or AD group" },
			{:name => "debug", :type => "boolean", 
				:required => false, 
				:default => false, 
				:description => "Debug Flag" },
			{:name => "proxy_string", 
				:type => "string", 
				:required => false, 
				:default => "",
				:description => "A Proxy Server String" }
		]
	}
end


def run(options)
	super
	
	print_good "DONE! #{metadata[:name]} got arguments: #{@options}"
	return

	#debug flag
	@debug = @options[:debug]

	#assign our arguments to specific vars
	@api_host = @options[:kenna_api_host]
	@api_token = @options[:kenna_api_token]
	@csv_file = @options[:csv_file]
	@email_col = @options[:email_column]
	@firstname_col = @options[:firstname_column]
	@lastname_col = @options[:lastname_column]
	@role_col =  @options[:role_column]
	@proxy_string = @options[:proxy_string]


	#Variables we'll need later
	@role_post_url = "https://#{@api_host}/roles"
	@user_post_url = "https://#{@api_host}/user"
	@headers = {'content-type' => 'application/json', 'X-Risk-Token' => @api_token }
	@role_found = false
	@role_list = ''
	@user_list = ''
	@user_file_list = []
	@user_id = ''

	num_lines = CSV.read(@csv_file).length
	puts "Found #{num_lines} lines."
	start_time = Time.now


	# Pull Existing Roles and Users from Kenna Instance
	# and store for lookups
	@role_list = JSON.parse(pull_roles_list)
	@user_list = JSON.parse(pull_user_list)

	output_filename = "output/user-role-sync_log-#{start_time.strftime("%Y%m%dT%H%M")}.txt"
	@log_output = File.open(output_filename,'a+')
	@log_output << "Processing CSV total lines #{num_lines}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
	# binding.pry

	puts @role_list if @debug
	puts @user_list if @debug

	# Iterate through CSV
	# CSV.foreach(@csv_file, :headers => true) do |row|
	# Changed loop from the line above to accommodate for a hidden BOM byte at the beginning of files created by Excel.
	CSV.open(@csv_file, 'r:bom|utf-8', :headers => true) do |csv|
		csv.each() do |row|

			current_line = $.
			email_address = nil
			first_name = nil
			last_name = nil
			role_name = nil

			email_address = row[@email_col].downcase
			first_name = row[@firstname_col]
			last_name = row[@lastname_col]
			role_name = row[@role_col]

			#append to list
			@user_file_list << row[@email_col]
			puts "------"  if @debug
			puts @user_file_list  if @debug
			puts "------"  if @debug

			puts "Email:#{email_address} , First:#{first_name} , Last:#{last_name} , Role:#{role_name}"
			@log_output << "\r" + "Email:#{email_address} , First:#{first_name} , Last:#{last_name} , Role:#{role_name}"

			if !role_exists(role_name)
				# Role Doesn't Exist
				puts "Role Does Not Exist. Creating Role."
				@log_output <<  "\r" + "Role Does Not Exist. Creating Role."
				create_role(role_name)
				#Refresh Role List
				@role_list = JSON.parse(pull_roles_list)
			else
				puts "Role Already Exists."
				@log_output << "\r" + "Role Already Exists."
			end

			if !user_exists(email_address)
				# User Doesn't Exist
				puts "User Does Not Exist. Creating User."
				@log_output << "\r" + "User Does Not Exist. Creating User."
				create_user(first_name,last_name,email_address, role_name)
			else
				# User Exists
				puts "User Already Exists. Updating User."
				@log_output << "\r" +  "User Already Exists. Updating User."
				update_user(@user_id.to_s,first_name,last_name,email_address, role_name)
				@user_id = ''
			end
			sleep(2)
		end
	end


	# Remove Users not included in the new data file
	# puts "REMOVING USERS!!!"

	# remove_users

	puts "DONE!"
	@log_output << "\r" +  "DONE!"
	@log_output.close
end



def pull_roles_list
	begin
		query_post_return = RestClient::Request.execute(
			method: :get,
			proxy: @proxy_string,
			url: @role_post_url,
			# payload: json_data,
			headers: @headers
		) 

	rescue Exception => e
		puts e.message  
		puts e.backtrace.inspect
		@log_output << "\r" +  e.message
	    @log_output << "\r" +  e.backtrace.inspect
	end
end

def pull_user_list
	begin
		query_post_return = RestClient::Request.execute(
			method: :get,
			proxy: @proxy_string,
			url: @user_post_url,
			# payload: json_data,
			headers: @headers
		) 

	rescue Exception => e
		puts e.message  
		puts e.backtrace.inspect
		@log_output << "\r" +  e.message
	    @log_output << "\r" +  e.backtrace.inspect
	end
end

def role_exists(role_name)

	@role_list["roles"].any? {|r1| r1['name']==role_name}
end

def create_role(role_name)
	json_data = {
		"role" =>
		{
			"name" => role_name.strip,
			"access_level" => "read"
        }
    }
    puts json_data if @debug

	begin
		query_post_return = RestClient::Request.execute(
			method: :post,
			proxy: @proxy_string,
			url: @role_post_url,
			payload: json_data,
			headers: @headers
		) 

	rescue Exception => e
		puts e.message  
		puts e.backtrace.inspect
	end
end

def user_exists(email)
	# @user_list["users"].any? {|r1| r1['email']==email}

	user = @user_list["users"].find {|r1| r1['email']==email.downcase}
	if user 
		@user_id = user["id"]
	else
		user
	end
end

def create_user(fname,lname,email,role_name)
	json_data = {
		"user" =>
		{
			"firstname"=>fname,
			"lastname"=>lname,
			"email"=>email,
			"role"=>role_name
        }
    }
	#puts json_data
	begin
		query_post_return = RestClient::Request.execute(
			method: :post,
			proxy: @proxy_string,
			url: @user_post_url,
			payload: json_data,
			headers: @headers
	    )
	rescue RestClient::UnprocessableEntity => e
		puts e.message
		puts "Unable to create this user (email:#{email})"
		@log_output << "\r" +  e.message
		@log_output << "\r" +  "Unable to create this user (email:#{email})"
	rescue Exception => e
		puts e.message
	    puts e.backtrace.inspect
		@log_output << "\r" +  e.message
	    @log_output << "\r" +  e.backtrace.inspect
	end
end

def update_user(uid,fname,lname,email,role_name)

	user = @user_list["users"].find {|r1| r1['email']==email.downcase}

	# binding.pry

	# Check for Admin users
	if user['role'] == 'administrator'
		puts "User #{email} is Administrator and will not be updated."
		@log_output << "\r" + "User #{email} is Administrator and will not be updated."
	else
	
		json_data = {
			"user" =>
			{
				"firstname"=>fname,
				"lastname"=>lname,
				"email"=>email,
				"role"=>role_name
	        }
	    }
		puts json_data if @debug
		
		url = @user_post_url + '/'+ uid
		puts url if @debug

		# binding.pry

		# Check for Role change
		if user['role'] != role_name 
			puts "ROLE CHANGE: User #{email} - #{user['role']} => #{role_name}."
			@log_output << "\r" + "ROLE CHANGE: User #{email} - #{user['role']} => #{role_name}."
		end

		begin
			query_post_return = RestClient::Request.execute(
				method: :put,
				proxy: @proxy_string,
				url: url,
				payload: json_data,
				headers: @headers
		    )
		rescue RestClient::UnprocessableEntity => e
			puts e.message
			puts "Unable to update this user (id:#{uid} email:#{email})"
			@log_output << "\r" +  e.message
			@log_output << "\r" +  "Unable to update this user (id:#{uid} email:#{email})"
		rescue Exception => e
			puts e.message
		    puts e.backtrace.inspect
			@log_output << "\r" +  e.message
		    @log_output << "\r" +  e.backtrace.inspect
		end
	end
end

def delete_user(uid)
	url = @user_post_url + '/'+ uid
	puts url #if @debug

	begin
		query_post_return = RestClient::Request.execute(
			method: :delete,
			proxy: @proxy_string,
			url: url,
			headers: @headers
	    )
	rescue RestClient::UnprocessableEntity => e
		puts e.message
		puts "Unable to delete this user (id:#{uid})"
		@log_output << "\r" +  e.message
		@log_output << "\r" +  "Unable to delete this user (id:#{uid})"
	rescue Exception => e
		puts e.message
	    puts e.backtrace.inspect
		@log_output << "\r" +  e.message
	    @log_output << "\r" +  e.backtrace.inspect
	end
end

def field_values(array_of_hashes, *fields)
  array_of_hashes.map do |hash|
    hash.values_at(*fields)
  end
end

def remove_users
	
	# binding.pry
	# puts "in remove_users"

	curr_users_array = field_values(@user_list["users"], "id", "email")

	curr_users_array.each do |id, email|
		# binding.pry
		if !@user_file_list.include? email
			puts "Deleting #{email} with ID: #{id}"
			@log_output << "\r" +  "Deleting #{email} with ID: #{id}"
			delete_user(id.to_s)
		end
	end

end

end
end
end