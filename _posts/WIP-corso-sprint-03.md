---
layout: post
title: Corso! Sprint 03
tags: [journeys, Corso!]
---

This is the first one on 2026, after vacations with no computer, just enjoying nature, surf and reflecting where I am headed. The sprint 03 goal was make Corso! more reliable for beta usage, we will be covering the progress next.

## Adding a user context

Corso! is live on Azure and one of points that I was not happy is that pretty much anyone could access the vault, even though on Sprint 02 we secured that with Cookie authentication in conjunction with a master password, I'd not like to let it open to anyone try brute-force the master password. I can leverage reliable features from Azure, one of them is "easy auth", a built-in secure authentication mechanism that does not require any code change, it pretty much add a front-door to your application and only invited users can view it.

![easy auth]({{'assets/images/corso-sprint-03/easy-auth.png' | relative_url}})

I'll not cover details in depth because I believe it is intuitive, there is a well known microsoft documentation how to use it. In summary you can "Add Provider", choose the authentication provider as you prefer, in my case I am using the MS one in combination with Microsoft Entra ID I can even invite external users that are interested at Corso! I did the test with another gmail account.

![corso ms auth]({{'assets/images/corso-sprint-03/corso-ms-auth.png' | relative_url}})

## Csv Upload

To make it useful somehow, I would need to dump all my registered accounts from 1Password to Corso! I found that it is possible to extract a CSV from there, and all relevant information I need is contained in the file. My decision was to create an upload mechanism tailored for the 1Password CSV file.

Usually, the default decision is using a library that can parse CSV files. Parsing can contain so many edge cases that sometimes makes sense to use it. However, the philosophy here is to use as little 3rd-party code as possible only in areas where there is an evident security risk I off the work to someone who has already went through the path.

Most of the features we've been building so far were not carrying heavy logic, so manual testing was enough to guarantee correctness. In the case of a parser, it's a little different. I'll read a CSV string and parse it into some C# `POCO` using reflection, which adds some spice to the game.

Unit tests will be a smart way to guarantee that I am moving forward correct and in a good pace.

The parser design will take 2 steps: first, Validation, I’ll guarantee this is a valid and parsable CSV file; second, the parse itself. Below is the controller using the parser.

```c#
[HttpPost("import")]
public async Task<ActionResult> Import(IFormFile file)
{  
    if(file is null || file.Length == 0)
    {
        return this.BadRequestProblem("File", $"The file {file?.FileName} was not imported because is empty.");
    }

    using var stream =  file.OpenReadStream();
    var validation = await csvParser.ValidateAsync<Account>(stream, _ => _.Id);
    
    if(validation.Error is not null)
    {
        return this.BadRequestProblem("File", validation.Error.Message);
    }

    var accounts = await csvParser.ParseAsync<Account>(stream, _ => _.Id);
    await vault.UnLockAsync();
    
    foreach(var account in accounts)
    {
        vault.Add(account);
    }

    await vault.LockAsync();
    return Ok();
}
```

I accept a file as input and open the stream that guarantees I'll not exhaust server memory, usually I am dealing with small files which makes things easier and most of them are buffered into memory, but larger files the framework saves it in a temp location, since this multi-part reading that contains boundaries we are able to read in parts without crashing the app. After opening the stream I can delegate the job to the parser, if any error encountered we are returning a bad request though some helper method I wrote to guarantee consistency with Problem details pattern that I've been using so far. 

## The parser

### Validation first
I exposed a validation mechanism, to help developer guarantee the file is consistent before trying to parse it, since the parse method throws exception if finds the input is not in the expected format, so it will not be able to conclude the operation the ValidateAsync helps in a way to avoid let it throw and be handled on app level which often is not a good idea, there are performance concerns when dealing with api and if you can always provide a way to avoid Exception to be thrown then better. The Exception would be more as a big warning to the developer to act promptly at the issue.

As mentioned before I choose write unit tests for this case, since the parser logic can be complex with lots of cases easy to break, but I would never write unit tests for the whole app specially in early stages, when you still collecting feedback where the right abstractions needs to play.

*Tests*

```c#
[Fact(DisplayName = "When validate it should return a error message when header is empty")]
    public async Task EmptyHeader()
    {
        //Arrange
        var emptyCsv = string.Empty;

        //Act
        var actual = await _csvParser.ValidateAsync<Poco>(emptyCsv.ToMemoryStream());

        //Assert
        Assert.False(actual.Succeeded);
        Assert.Equal(CsvParser.ErrorTypes.EmptyHeader, actual.Error?.Type);
    }

    [Fact(DisplayName = "When validate it should return a error message when header does not match `POCO`")]
    public async Task HeaderDoesNotMatchPoco()
    {
        //Arrange
        var badCsvHeader = @"badName, badQuantity
                           testName, 20";

        //Act
        var actual = await _csvParser.ValidateAsync<Poco>(badCsvHeader.ToMemoryStream());

        //Assert
        Assert.False(actual.Succeeded);
        Assert.Equal(CsvParser.ErrorTypes.HeaderDoesNotMatch, actual.Error?.Type);
    }

    [Fact(DisplayName = "When validate it should return success when header matches `POCO`")]
    public async Task MatchingHeader()
    {
        //Arrange
        var csvContent = @"title, quantity, username
                          titleName,testName, 20";

        //Act
        var actual = await _csvParser.ValidateAsync<Poco>(csvContent.ToMemoryStream());

        //Assert
        Assert.True(actual.Succeeded);
        Assert.Null(actual.Error);
    }

    [Fact(DisplayName = "after validate stream it should be able to read again")]
    public async Task CanReadStreamAfterValidation()
    {
        //Arrange
        var someStream = new MemoryStream([1, 2, 3]);
        
        //Act
        await _csvParser.ValidateAsync<Poco>(someStream);
        
        //Assert
        Assert.True(someStream.CanRead);
        Assert.Equal(0, someStream.Position);
    }

```

If you realize the tests are small focused and I wrote a couple of them, to guarantee the main validation logic works, I avoid as much as I can using test-doubles (Mocks, Stubs, Fakes..) There are cases they can help specially when dealing with a external system that you do not have control over, you can mimic behaviors that can enhance testability. In my case I am using a memory stream to pretend a Csv in a stream and it worked pretty well, one metric that I pay attention is how easy is to write those tests and how often when they break it catches a real bug. If your tests often breaks and no bug is encountered this a sign that your test suite is too fragile and you should rethink your approach how to write them. Maybe you are still exploring the design, maybe you are testing stuff that you should not because is way too close to the implementation detail, in many of those cases the best approach is to delete the test and come later when the idea is more mature. In terms of conventions I tried many different ones and I stick with naming my tests by scenarios e.g MatchingHeader and a more descriptive statement on display name using as guidance gherkin syntax but not getting it into the bones, I also think split the Arrange, Act, Assert sections is useful.

*Code*

```c#

public async Task<ValidationResult> ValidateAsync<T>(Stream stream, params Expression<Func<T, object>>[] doNotValidate)
{
    if(!stream.CanSeek)
    {
        throw new InvalidOperationException("Csv parser only support seekable streams!");
    }

    try
    {
        using var reader = new StreamReader(stream, leaveOpen: true);
        var header = await reader.ReadLineAsync();

        if (string.IsNullOrWhiteSpace(header))
        {
            return new ValidationResult()
            {
                Error = new Error
                {
                    Type = ErrorTypes.EmptyHeader,
                    Message = $"The header is empty."
                }
            };
        }

        var fieldsFromHeader = header.Split(",", StringSplitOptions.TrimEntries);
        var givenType = typeof(T);
        var propertiesFromGivenType = givenType.GetProperties();
        var missingFields = new List<string>();
        var doNotValidateNames = GetNames(doNotValidate);

        foreach (var prop in propertiesFromGivenType)
        {
            if(doNotValidateNames.Contains(prop.Name, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!fieldsFromHeader.Contains(prop.Name, StringComparer.OrdinalIgnoreCase))
            {
                missingFields.Add(prop.Name.ToLower());
            }
        }

        if(missingFields.Count > 0)
        {
            return new ValidationResult()
            {
                Error = new Error
                {
                    Type = ErrorTypes.HeaderDoesNotMatch,
                    Message = $"The header does not match with provided type: {givenType.Name}, missing fields: {string.Join(", ", missingFields)}."
                }
            };
        }

        return new ValidationResult()
        {
            Succeeded = true
        };
    }
    finally
    {
        //Always set stream to the begin for re-read.
        stream.Seek(0, SeekOrigin.Begin);
    }
}

```

At first, there’s a validation for seekable streams. This happens because the class is designed for two steps, and I want the validation to avoid producing any side effects on the caller’s stream. That’s why the stream remains open, and at the end of the operation we reset it to the beginning inside the finally block. If the stream isn’t seekable, I can’t rewind it.

I also added a `doNotValidate` option to exclude `POCO` properties that don’t perfectly match the CSV columns for example, the ID of an account, which is generated by the Vault. The loop uses reflection to compare property names from the given type against the CSV header. If any property isn’t found, it’s added to the missing fields collection, and later an error is returned to help identify where the mismatch occurred.

### Now parse it

I'll not go over the parsing logic tests but it followed same guidelines from the validation logic, small, focused, easy to write and most important give feedback if I am doing any B/S. Below is the implementation, it was simple to write for my specific use case, not depending on any library at least for now sounds the right choice.

*Code*

```c#

public async Task<IEnumerable<T>> ParseAsync<T>(Stream stream, params Expression<Func<T, object>>[] excludeFromParsing)
{
    var reader = new StreamReader(stream, leaveOpen: true);
    
    var headerLine = await reader.ReadLineAsync()
        ?? throw new InvalidOperationException("File header cannot be empty!");
    
    var excludedPropNames = GetNames(excludeFromParsing);
    var indexesFromType = MapIndexesFromType<T>(headerLine, excludedPropNames);
    List<T> parsedItems = []; 
    //starts at 2 because of header.
    var lineNumber = 2;
    while(!reader.EndOfStream)
    {
        var line = await reader.ReadLineAsync()
            ?? throw new InvalidOperationException($"Csv line {lineNumber} is empty.");

        var parsed = ParseItem<T>(indexesFromType, line, lineNumber);
        parsedItems.Add(parsed);
        lineNumber++;
    }

    return parsedItems;
}

```

The function is smaller than `Validation()`, so I took more time to create abstractions that make it easier to maintain. We start by extracting property names from the expression tree to identify which properties to exclude from parsing. I use a dictionary returned from `MapIndexesFromType()` that tells me the position for each property value. For example: account name at index 0, title at index 1. This map serves as the foundation for parsing each CSV line using reflection to assign values to the correct properties.

Finally, we loop through the stream, reading each line and converting it to the target type. The `ParseItem()` method splits each line by commas and uses the map to determine which array position corresponds to each property, then assigns the right values through reflection.

## Sprint 04

The next sprint will be the last one working on Corso! I'll take a break to focus on other fronts, like open-source, however still documenting everything on this blog that I find relevant.

I already started to do some beta usage of the app and it is almost there. There is some little inconvenience, since this is free hosting on Azure sometimes this is pretty slow to bootstrap, but I can stay with it.

The last sprint before focusing on anything else, I'll fix the user experience on mobile which is not that good, and I'll totally `vibe code` this one, sharing my impressions and some thoughts about AI. 