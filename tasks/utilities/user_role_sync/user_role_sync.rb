# frozen_string_literal: true

module Kenna
  module Toolkit
    class UserRoleSync < Kenna::Toolkit::BaseTask
      def self.metadata
        {
          id: "user_role_sync",
          name: "User Role Sync",
          description: "This task creates users and assigns them to roles via the API",
          options: [
            { name: "kenna_api_key",
              type: "api_key",
              required: true,
              default: nil,
              description: "Kenna API Key" },
            { name: "kenna_api_host",
              type: "hostname",
              required: false,
              default: "api.kennasecurity.com",
              description: "Kenna API Hostname" },
            { name: "csv_file",
              type: "filename",
              required: true,
              default: "tasks/user_role_sync/users.csv",
              description: "Path to CSV file with user and role information, relative to #{$basedir}" },
            { name: "email_column",
              type: "string",
              required: false,
              default: "EmailAddress",
              description: "Header for the CSV file column containing an email address" },
            { name: "firstname_column",
              type: "string",
              required: false,
              default: "FirstName",
              description: "Header for the CSV file column containing a first name" },
            { name: "lastname_column",
              type: "string",
              required: false,
              default: "Lastname",
              description: "Header for the CSV file column containing a last name" },
            { name: "role_column",
              type: "string",
              required: false,
              default: "ADGroup",
              description: "Header for the CSV file column containing a role or AD group" },
            { name: "remove_users",
              type: "boolean",
              required: false,
              default: false,
              description: "Optional parameter to remove users not in data file from Kenna system" },
            { name: "role_exclusions",
              type: "string",
              required: false,
              default: "",
              description: "Optional parameter. Comma-delimited list of role IDs to exclude from updates." },
            { name: "debug",
              type: "boolean",
              required: false,
              default: false,
              description: "Debug Flag" }
          ]
        }
      end

      def run(options)
        super

        # print_good "#{metadata[:name]} got arguments: #{@options}"

        # debug flag
        @debug = @options[:debug]

        # assign our arguments to specific vars
        @api_host = @options[:kenna_api_host]
        @api_token = @options[:kenna_api_key]
        @csv_file = @options[:csv_file]
        @email_col = @options[:email_column]
        @firstname_col = @options[:firstname_column]
        @lastname_col = @options[:lastname_column]
        @role_col = @options[:role_column]
        @remove_users = @options[:remove_users]
        @role_exclusions = @options[:role_exclusions]

        # Variables we'll need later
        @role_post_url = "https://#{@api_host}/roles"
        @user_post_url = "https://#{@api_host}/users"
        @headers = { "content-type" => "application/json", "X-Risk-Token" => @api_token }
        @role_found = false
        @role_list = ""
        @user_list = ""
        @user_file_list = []
        @user_id = ""

        csv_file_path = "#{$basedir}/#{@csv_file}"
        print_good "Attempting to read from #{csv_file_path}"
        num_lines = CSV.read(csv_file_path).length
        print_good "Found #{num_lines} lines."
        start_time = Time.now

        # # Pull Existing Roles and Users from Kenna Instance
        # # and store for lookups
        # @role_list = JSON.parse(pull_roles_list)
        # @user_list = JSON.parse(pull_user_list)

        output_filename = "#{$basedir}/output/user-role-sync_log-#{start_time.strftime('%Y%m%dT%H%M')}.txt"
        @log_output = File.open(output_filename, "a+")
        @log_output << "Processing CSV total lines #{num_lines}... (time: #{Time.now}, start time: #{start_time})\n"
        # binding.pry

        # Pull Existing Roles and Users from Kenna Instance
        # and store for lookups
        @role_list = JSON.parse(pull_roles_list)
        @user_list = JSON.parse(pull_user_list)

        print_good @role_list if @debug
        print_good @user_list if @debug

        # Checking to ensure all exclusions are integers
        # @role_exclusions.split(",").all? {|i| true if Integer(i) rescue false }

        print_good "Excluding the following Kenna Roles:"
        @role_exclusions.split(",").map do |role_id|
          role = @role_list["roles"].detect { |r| r["id"] == role_id.to_i }
          print_good "\t#{role['id']} \t-- \t#{role['name']}"
        end

        # Iterate through CSV
        # CSV.foreach(@csv_file, :headers => true) do |row|
        # Changed loop from the line above to accommodate for a hidden BOM byte at the beginning of files created by Excel.
        CSV.open(csv_file_path, "r:bom|utf-8", headers: true) do |csv|
          csv.each do |row|
            email_address = row[@email_col].downcase
            first_name = row[@firstname_col]
            last_name = row[@lastname_col]
            role_name = row[@role_col]

            # append to list
            @user_file_list << row[@email_col]
            print_good "------" if @debug
            print_good @user_file_list if @debug
            print_good "------" if @debug

            print_good "------"
            print_good "Email:#{email_address} , First:#{first_name} , Last:#{last_name} , Role:#{role_name}"
            @log_output << "\rEmail:#{email_address} , First:#{first_name} , Last:#{last_name} , Role:#{role_name}"

            if role_exists(role_name)
              # Role Doesn't Exist
              print_error "Role Already Exists."
              @log_output << "\rRole Already Exists."
            else
              print_good "Role Does Not Exist. Creating Role."
              @log_output << "\rRole Does Not Exist. Creating Role."
              create_role(role_name)
              # Refresh Role List
              @role_list = JSON.parse(pull_roles_list)
            end

            if user_exists(email_address)
              # User Doesn't Exist
              print_error "User Already Exists. Updating User."
              @log_output << "\rUser Already Exists. Updating User."
              update_user(@user_id.to_s, first_name, last_name, email_address, role_name)
              @user_id = ""
            else
              # User Exists
              print_good "User Does Not Exist. Creating User."
              @log_output << "\rUser Does Not Exist. Creating User."
              create_user(first_name, last_name, email_address, role_name)
            end
            sleep(2)
          end
        end

        # Remove Users not included in the new data file
        if @remove_users
          print_good "REMOVING USERS!!!"
          remove_users
        end

        print_good "DONE!"
        @log_output << "\rDONE!"
        @log_output.close
      end

      def pull_roles_list
        puts @role_post_url
        RestClient::Request.execute(
          method: :get,
          url: @role_post_url,
          # payload: json_data,
          headers: @headers
        ).body
      rescue StandardError => e
        print_good e.message
        print_good e.backtrace.inspect
        @log_output << "\r#{e.message}"
        @log_output << "\r#{e.backtrace.inspect}"
      end

      def pull_user_list
        RestClient::Request.execute(
          method: :get,
          url: @user_post_url,
          # payload: json_data,
          headers: @headers
        ).body
      rescue StandardError => e
        print_good e.message
        print_good e.backtrace.inspect
        @log_output << "\r#{e.message}"
        @log_output << "\r#{e.backtrace.inspect}"
      end

      def role_exists(role_name)
        @role_list["roles"].any? { |r1| r1["name"] == role_name }
      end

      def create_role(role_name)
        json_data = {
          "role" =>
          {
            "name" => role_name.strip,
            "access_level" => "read"
          }
        }
        print_good json_data if @debug

        begin
          RestClient::Request.execute(
            method: :post,
            url: @role_post_url,
            payload: json_data,
            headers: @headers
          )
        rescue StandardError => e
          print_error e.message
          print_error e.backtrace.inspect
        end
      end

      def user_exists(email)
        # @user_list["users"].any? {|r1| r1['email']==email}

        user = @user_list["users"].find { |r1| r1["email"] == email.downcase }
        if user
          @user_id = user["id"]
        else
          user
        end
      end

      def create_user(fname, lname, email, role_name)
        json_data = {
          "user" =>
          {
            "firstname" => fname,
            "lastname" => lname,
            "email" => email,
            "role" => role_name
          }
        }
        # print_good json_data
        begin
          RestClient::Request.execute(
            method: :post,
            url: @user_post_url,
            payload: json_data,
            headers: @headers
          )
        rescue RestClient::UnprocessableEntity => e
          print_good e.message
          print_error "Unable to create this user (email:#{email})"
          @log_output << "\r#{e.message}"
          @log_output << "\rUnable to create this user (email:#{email})"
        rescue StandardError => e
          print_error e.message
          print_error e.backtrace.inspect
          @log_output << "\r#{e.message}"
          @log_output << "\r#{e.backtrace.inspect}"
        end
      end

      def update_user(uid, fname, lname, email, role_name)
        user = @user_list["users"].find { |r1| r1["email"] == email.downcase }

        # Check for Admin users
        if user["role"] == "administrator"
          print_good "User #{email} is Administrator and will not be updated."
          @log_output << "\rUser #{email} is Administrator and will not be updated."
        elsif @role_exclusions.include? user["role_id"].to_s
          print_good "User #{email} has role of \"#{user['role']}\" is on exclusion list and will not be updated."
          @log_output << "\rUser #{email} has role of \"#{user['role']}\" is on exclusion list and will not be updated."
        else

          json_data = {
            "user" =>
            {
              "firstname" => fname,
              "lastname" => lname,
              "email" => email,
              "role" => role_name
            }
          }
          print_good json_data if @debug

          url = "#{@user_post_url}/#{uid}"
          print_good url if @debug

          # binding.pry

          # Check for Role change
          if user["role"] != role_name
            print_good "ROLE CHANGE: User #{email} - #{user['role']} => #{role_name}."
            @log_output << "\rROLE CHANGE: User #{email} - #{user['role']} => #{role_name}."
          end

          begin
            RestClient::Request.execute(
              method: :put,
              url: url,
              payload: json_data,
              headers: @headers
            )
          rescue RestClient::UnprocessableEntity => e
            print_error e.message
            print_error "Unable to update this user (id:#{uid} email:#{email})"
            @log_output << "\r#{e.message}"
            @log_output << "\rUnable to update this user (id:#{uid} email:#{email})"
          rescue StandardError => e
            print_error e.message
            print_error e.backtrace.inspect
            @log_output << "\r#{e.message}"
            @log_output << "\r#{e.backtrace.inspect}"
          end
        end
      end

      def delete_user(uid)
        url = "#{@user_post_url}/#{uid}"
        print_good url # if @debug

        begin
          RestClient::Request.execute(
            method: :delete,
            url: url,
            headers: @headers
          )
        rescue RestClient::UnprocessableEntity => e
          print_error e.message
          print_error "Unable to delete this user (id:#{uid})"
          @log_output << "\r#{e.message}"
          @log_output << "\rUnable to delete this user (id:#{uid})"
        rescue StandardError => e
          print_error e.message
          print_error e.backtrace.inspect
          @log_output << "\r#{e.message}"
          @log_output << "\r#{e.backtrace.inspect}"
        end
      end

      def field_values(array_of_hashes, *fields)
        array_of_hashes.map do |hash|
          hash.values_at(*fields)
        end
      end

      def remove_users
        # binding.pry
        # print_good "in remove_users"

        curr_users_array = field_values(@user_list["users"], "id", "email", "role_id", "role")

        curr_users_array.each do |id, email, role_id, role_name|
          # binding.pry
          next if @user_file_list.include? email

          # Check for Admin users
          if role_name == "administrator"
            print_good "User #{email} is Administrator and will not be removed."
            @log_output << "\rUser #{email} is Administrator and will not be removed."
          elsif @role_exclusions.include? role_id.to_s
            print_good "User #{email} has role of \"#{role_name}\" is on exclusion list and will not be removed."
            @log_output << "\rUser #{email} has role of \"#{role_name}\" is on exclusion list and will not be removed."
          else
            print_good "Deleting #{email} with ID: #{id} and ROLE: \"#{role_name}\""
            @log_output << "\rDeleting #{email} with ID: #{id} and ROLE: \"#{role_name}\""
            delete_user(id.to_s)
          end
        end
      end
    end
  end
end
