# frozen_string_literal: true

shared_examples "a json stream" do |options = {}|
  it "handles a simple array" do
    check_roundtrip(["abc"], options)
  end

  it "handles a simple object" do
    check_roundtrip({ "foo" => "bar" }, options)
  end

  it "handles one level of array nesting" do
    check_roundtrip([["def"], "abc"], options)
    check_roundtrip(["abc", ["def"]], options)
  end

  it "handles one level of object nesting" do
    check_roundtrip({ "foo" => { "bar" => "baz" } }, options)
  end

  it "handles one level of mixed nesting" do
    check_roundtrip({ "foo" => ["bar", "baz"] }, options)
    check_roundtrip([{ "foo" => "bar" }], options)
  end

  it "handles multiple levels of mixed nesting" do
    check_roundtrip({ "foo" => ["bar", { "baz" => "moo", "gaz" => ["doo"] }, "kal"], "jim" => ["jill", ["john"]] }, options)
    check_roundtrip(["foo", { "bar" => "baz", "moo" => ["gaz", ["jim", ["jill"]], "jam"] }], options)
  end
end
