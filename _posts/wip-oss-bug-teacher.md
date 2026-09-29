---
layout: post
title: Embrace bug, your mundane teacher!
tags: [journeys, oss-guide]
---

In the next chapter in my OSS journey, we will explore my latest PR fixing a bug in [Kestrel](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/servers/kestrel?view=aspnetcore-10.0){:target="blank" rel="noopener"} web server. How embracing a bug is the best thing a engineer can choose to grow knowledge in a code base.

## Switching focus

Past months I was little overwhelmed, some of my contributions did not get any traction, looking for a hotter project that I knew things would move in a good pace, [ASP.NET Core](https://dotnet.microsoft.com/pt-br/apps/aspnet){:target="blank" rel="noopener"} came up as perfect alternative; any .NET developer on the web use the framework, the community is active and so far pretty good to welcome. 

The codebase is huge, best strategy was focusing in some particular area of the framework. Security is one of the aspect of software that has always caught my attention, following the article you will find a small contribution to a crypto library, that was satisfying however I realized the area is way too narrow and specific.

I prefer act on something that I can combine more techniques, a web server such as Kestrel would be a sweet spot, I can combine security, networking, parallelism, performance and more. Checking the list of open issues I found [this](https://github.com/dotnet/aspnetcore/issues/68371){:target="blank" rel="noopener"}, such a beautiful bug to start.

## A man is not an island

Trying to avoid past mistakes just pulling my head down to the keyboard, my first attitude was making sure I understood what is in the ticket aligning my approach with the maintainer, the goal was a healthy small interaction to know people and connect. 

First step, clone the repo, build and execute tests; on README files is easy to find guidance since framework is huge, it is just counter-productive load all modules from root. Setting up only Kestrel module was enough for now.

Next step "analysis", the maintainer has provided useful information in the ticket, the code was not that hard to figure out, but I had to confirm my gut, follow the discussion [here](https://github.com/dotnet/aspnetcore/issues/68371){:target="blank" rel="noopener"}, I think this a good example of healthy interaction in Open-Source world.

## Bug summary

About the issue, in Kestrel's HTTP implementation, when the server received newline characters `\n\r` in [trailers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Trailer){:target="blank" rel="noopener"} and HPACK [Dynamic table](https://httpwg.org/specs/rfc7541.html#dynamic.table){:target="blank" rel="noopener"} retrieval the values were not being refused, then server wast not in compliance with [RFC 7540 10.3](https://www.rfc-editor.org/rfc/rfc7540.html#section-10.3){:target="blank" rel="noopener"}.

The validation was present in the code already but for those paths it was turned off, the approach was turn it on and writing tests as regression. Tests has showed up more challenges than the bug fix itself forcing me go into the bones of the HTTP protocol and HPACK. 

Later we will explore each test and the concepts behind each, below is the bug fix: 

`HttpProtocol.cs` method `OnTrailers`

```diff 
    string key = name.GetHeaderName();
-   var valueStr = value.GetRequestHeaderString(key, HttpRequestHeaders.EncodingSelector, checkForNewlineChars: false);
+   var valueStr = value.GetRequestHeaderString(key, HttpRequestHeaders.EncodingSelector, checkForNewlineChars: true);
    RequestTrailers.Append(key, valueStr);
     
```
`Http2Connection.cs` method `OnHeaderCore`

```diff
{
    UpdateHeaderParsingState(value, GetPseudoHeaderField(name));

-   _currentHeadersStream.OnHeader(name, value, checkForNewlineChars: false);
+   _currentHeadersStream.OnHeader(name, value, checkForNewlineChars: true);
}

```

## Testing trailers

Trailer headers are common feature between all HTTP versions, so I had to guarantee the behavior for all of them. HTTP 3 I had to write a brand new test at stream level not a challenge though. 

I could use the test high level api maintained by the team in base classes, following the test patterns you are able to write similar stuff, I will paste snippet below without much details, then we can focus on HTTP 2 where offered a bigger challenge.

```csharp
    [Theory]
    [InlineData("\r")]
    [InlineData("\n")]
    [InlineData("\r\n")]
    public async Task RequestTrailers_ContainsNewlines(string newlineChars)
    {

        var headers = new[]
        {
            new KeyValuePair<string, string>(InternalHeaderNames.Method, "GET"),
            new KeyValuePair<string, string>(InternalHeaderNames.Path, "/"),
            new KeyValuePair<string, string>(InternalHeaderNames.Scheme, "http"),
        };

        var trailerWithNewlines = new[]
        {
            new KeyValuePair<string, string>("contains-newlines", newlineChars),
        };

        var requestStream = await Http3Api.InitializeConnectionAndStreamsAsync(_noopApplication, headers, endStream: false);
        await requestStream.SendHeadersAsync(trailerWithNewlines, endStream: true);

        await requestStream.WaitForStreamErrorAsync(
            Http3ErrorCode.MessageError,
            expectedErrorMessage: CoreStrings.BadRequest_MalformedRequestInvalidHeaders);
    }
```

The test above as mentioned is straight forward we send the required headers to the server "Method", "Path" and "Scheme" when connection is initialized, I do not close the stream. Next I send the headers closing the stream, so the server identify it as trailers. Finally I wait for the proper error specified in RFC "Malformed Request".

In regards HTTP 2 the test was already available I just had to extend the test data, that sounded lower effort but I end up in a quest of knowledge.

*Http2ConnectionTests.cs*
```csharp
[Theory]
[MemberData(nameof(IllegalTrailerData))]
public async Task HEADERS_Received_WithTrailers_ContainsIllegalTrailer_ConnectionError(byte[] trailers, string expectedErrorMessage)
{
    await InitializeConnectionAsync(_readTrailersApplication);

    await SendHeadersAsync(1, Http2HeadersFrameFlags.END_HEADERS, _browserRequestHeaders);
    await SendHeadersAsync(1, Http2HeadersFrameFlags.END_HEADERS | Http2HeadersFrameFlags.END_STREAM, trailers);

    await WaitForConnectionErrorAsync<Http2ConnectionErrorException>(
        ignoreNonGoAwayFrames: false,
        expectedLastStreamId: 1,
        expectedErrorCode: Http2ErrorCode.PROTOCOL_ERROR,
        expectedErrorMessage: expectedErrorMessage);

    AssertConnectionEndReason(ConnectionEndReason.InvalidRequestHeaders);
}
```
I extended IllegalTrailerData adding tree new scenarios, ran the test to make sure it would fail and then patched the fix (TDD approach).

```diff
+   //Invalid header CR - contains-cr: \r
+   {
+       new byte[]{0x00, 0x0B}.Concat(Encoding.ASCII.GetBytes("contains-cr")).Concat(new byte[]{0x01, 0x0D}).ToArray(),
+       CoreStrings.BadRequest_MalformedRequestInvalidHeaders
+   },
+   //Invalid header LF - contains-lf: \n
+   {
+       new byte[]{0x00, 0x0B}.Concat(Encoding.ASCII.GetBytes("contains-lf")).Concat(new byte[]{0x01, 0x0A}).ToArray(),
+       CoreStrings.BadRequest_MalformedRequestInvalidHeaders
+   },
+   //Invalid header CR and LF - contains-crlf: \r\n
+   {
+       new byte[]{0x00, 0x0D}.Concat(Encoding.ASCII.GetBytes("contains-crlf")).Concat(new byte[]{0x02, 0x0D, 0x0A}).ToArray(),
+       CoreStrings.BadRequest_MalformedRequestInvalidHeaders
+   }
```
The test body itself is quite simple and the test API available makes easy to understand without digging to much in details, short explanation; it initialize a new HttpConnection within an application, which are pre instantiated in base class to attend various scenarios. An app is anything that you can process a Http request. 

After stablish a connection you can use existing APIs to data to the application, in case of trailer it needs to end the stream along with headers. Lately the test wait for the error to be returned, remember this is a web server so request are processed in a async loop, that's why the wait time.

Now the fun part, pay attention to the test data, how I end up with those bytes? Here is where HPACK start to play let's understand the basic of this encoding.

### HPACK

The way HTTP 1 and HTTP 2 transfer data has a drastic change from a pure hyper text protocol to a binary protocol. Human readability is a great advantage of text protocol's, but as  everything in computer science the convenience carries it's trade-offs, for machines the approach can be error-prone. 

Let's take such a bug a example, CR and LF for HTTP 2 is just any arbitrary data without any special meaning, but when we downgrade to HTTP 1 (common scenario working with legacy apps) same characters are treated as end of line, http smuggling can occur or even worse the HTTP response will split possibly being manipulated by an attacker more details on both:

[HTTP smuggling](https://geniwazir.medium.com/understanding-request-smuggling-a-deep-dive-into-http-exploits-06bc28b0358c){:target="blank" rel="noopener"}
[HTTP Splitting](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling/){:target="blank" rel="noopener"}

A binary protocol is by design protected, same characters would not have any impact or meaning, performance can be improved, which makes sense since this used everywhere. Another advantage from the binary approach is that now we can easily compress repeatable headers, since the protocol is stateless client and server often send same header key value pair in each request, here is where the HPACK helps us.

In the end of the article I'll forward useful articles for more detailed explanation; basically the client and server are able to maintain a dictionary per connection scope, this dictionary already contain static data which are common value often present in HTTP request e.g path:, method:, content-encoding: if the header is not in the list, such as: x-test-header : testValue it gets added to the dynamic table.

For this particular test I had to craft the bytes by myself by passing the HPACK encoder, the encoder available on test API convert everything to lower case, some scenarios are sensitive to this conversion making it not a viable option. 

Let's analyze the package below

```csharp
new byte[]{0x00, 0x0B}.Concat(Encoding.ASCII.GetBytes("contains-cr")).Concat(new byte[]{0x01, 0x0D}).ToArray(),
```
the first byte "0x00" tells the decoder this package is a "Literal Header Field without Indexing", the 0x0B is the length of the payload name "contains-cr", next I am using the ASCII encoding as a helper maintaining some readability. 

Next part is the length of the content payload "0x01" (just one byte) + the content itself in this case "CR" represented by the byte 0x0D.

Following two test cases, same logic: (HPACK Prefix) + (Name Length) + (Name Payload) + (Value Length) + (Value Payload).

## Asking for help

At this point, I was fairly confident to submit my PR for review. The maintainer has spotted a gap in my understanding, one of the tests that I wrote was not exercising HPACK dynamic table retrieval, previously I though the table would be indexed by name so if I sent "TestHeader" : "initialValue" and later "TestHeader" : "\n" would suffice, but my assumption was wrong. HPACK index names and values separately, in this case it would be treated as new entry, so it never reached out the path dynamic in the method `OnHeaderCore`

Bad test:

```csharp
    [Theory]
    [InlineData("\r")]
    [InlineData("\n")]
    [InlineData("\r\n")]
    public async Task HEADERS_Received_NewLineCharactersInDynamicTable_ConnectionError(string newLineChars)
    {
        var headers = new[]
        {
            new KeyValuePair<string, string>(InternalHeaderNames.Method, "GET"),
            new KeyValuePair<string, string>(InternalHeaderNames.Path, "/"),
            new KeyValuePair<string, string>(InternalHeaderNames.Scheme, "http"),
            new KeyValuePair<string, string>(InternalHeaderNames.Authority, "localhost:80"),
            new KeyValuePair<string, string>("TestHeader", "initialValue"),
        };

        await InitializeConnectionAsync(_noopApplication);
        await StartStreamAsync(1, headers, endStream: true);

        var headersWithNewLineChars = new[]
        {
            new KeyValuePair<string, string>(InternalHeaderNames.Method, "GET"),
            new KeyValuePair<string, string>(InternalHeaderNames.Path, "/"),
            new KeyValuePair<string, string>(InternalHeaderNames.Scheme, "http"),
            new KeyValuePair<string, string>(InternalHeaderNames.Authority, "localhost:80"),
            new KeyValuePair<string, string>("TestHeader", newLineChars),
        };

        await StartStreamAsync(3, headersWithNewLineChars, endStream: true);

        await WaitForConnectionErrorAsync<Exception>(
            ignoreNonGoAwayFrames: true,
            3,
            Http2ErrorCode.PROTOCOL_ERROR,
            "Malformed request: invalid headers.");

        AssertConnectionEndReason(ConnectionEndReason.InvalidRequestHeaders);
    }
```
 Code not exercised:

 ```csharp
 case HeaderType.Dynamic:
    // It is faster to set a header using a static table index than a name.
    if (staticTableIndex != null)
    {
        UpdateHeaderParsingState(value, GetPseudoHeaderField(staticTableIndex.GetValueOrDefault()));

        _currentHeadersStream.OnHeader(staticTableIndex.GetValueOrDefault(), indexOnly: false, name, value);
    }
    else
    {
        UpdateHeaderParsingState(value, GetPseudoHeaderField(name));

        //Change not validated by tests
        _currentHeadersStream.OnHeader(name, value, checkForNewlineChars: true);
    }
    break;
 ```

 I debugged my test to confirm it; after spend hours and days of research, I had to admit that I could not figure out this one by myself. Actually I did in some extent, but not confident that was the the most appropriate approach, to reach the line that I was interested on, the entry point would be `OnDynamicHeaderIndex` which is a kind of event handler for index headers emitted by HPACK decoder implementation.

 The decoder implementation exposes a test seam that I could inject a Dynamic table so my idea was to inject a poisoned table with bad values (newline chars) and later just call the event. 
 
 It would reach the branch `HeaderType.Dynamic`, but the Http2Connection class has a private instance of the decoder so I could not inject it into the server, than I would need to introduce another test seam at HttpConnection level then I would be able to work with a bad decoder. I do not agree changing production code design for the sake of tests. 
 
 Exploring it by calling the event to inspect internal behavior I found out a Debug assertion `Debug.Assert(_currentHeadersStream != null);` that means if I do not have a current stream opened it is considered a bad state. At this point not able to connect the dots, then I had ask for help. 
 
 I had to be little patient with the reply, that guy was nice enough to even code the test we were looking for, this the kind of collaboration which is appreciated:

 ```csharp
    [Theory]
    [InlineData("\r")]
    [InlineData("\n")]
    [InlineData("\r\n")]
    public async Task OnDynamicIndexedHeader_NewLineCharactersInValue_ConnectionError(string headerValue)
    {
        await InitializeConnectionAsync(_noopApplication);

        // Start a request header block without END_HEADERS so the connection has an active stream receiving headers.
        await SendHeadersAsync(streamId: 1, flags: Http2HeadersFrameFlags.END_STREAM, headers: _browserRequestHeaders);

        var value = Encoding.ASCII.GetBytes(headerValue);

        // Simulate HPackDecoder resolving a fully indexed dynamic-table entry.
        var exception = Assert.Throws<Http2ConnectionErrorException>(() =>
            _connection.OnDynamicIndexedHeader(index: null, name: "test-header"u8, value));

        Assert.Equal(Http2ErrorCode.PROTOCOL_ERROR, exception.ErrorCode);
        Assert.Equal(ConnectionEndReason.InvalidRequestHeaders, exception.Reason);
        Assert.Contains(CoreStrings.BadRequest_MalformedRequestInvalidHeaders, exception.Message);

        // Finish the intentionally incomplete header block and shut down normally.
        await SendEmptyContinuationFrameAsync(streamId: 1, flags: Http2ContinuationFrameFlags.END_HEADERS);
        await StopConnectionAsync(expectedLastStreamId: 1, ignoreNonGoAwayFrames: true);
        AssertConnectionNoError();
    }
 ```

 The missing piece was on how to maintain an active stream and this line did the job:

 ```csharp
    // Start a request header block without END_HEADERS so the connection has an active stream receiving headers.
    await SendHeadersAsync(streamId: 1, flags: Http2HeadersFrameFlags.END_STREAM, headers: _browserRequestHeaders);
 ```

 I don't send the flag END_HEADERS, so the server keep waiting for more header frames which probably will be the continuation, so now I am able to directly call `OnDynamicIndexedHeader` without throwing on Debug.Assert, passing the newline characters and finally exercising the change.

## Wrapping up

Several lessons was taken by fixing a bug, this is the work that often is not glamorous and mundane, but if you change your perspective and see as the best opportunity to learn something new it can become fun. 

We see the importance to stay humble, no matter how veteran you are, you can alway learn by admitting your weaknesses and asking for help when necessary.

Stay present, paying attention in my knowledge gap made me go after it, spending some hours revisiting papers and documentation. In near future with the arrival of LLMs, code is not bottleneck, so the combination of domain knowledge + computer science theory, will be the key. 

Making sure my foundations are sharp I can navigate between these domains, that's one of the reasons I came to OSS is the opportunity to contribute with the backbone of the web which will force me to revisit my foundation. 

Below are some links that worth reading and helped me to refresh the knowledge:

[HTTP 2 Explained](https://http2-explained.haxx.se){:target="blank" rel="noopener"}
[HTTP 3 Explained](https://http3-explained.haxx.se/){:target="blank" rel="noopener"}
[HPACK: Header Compression format for HTTP/2](https://medium.com/geekculture/hpack-header-compression-format-for-http-2-155a0b4934f7){:target="blank" rel="noopener"}



