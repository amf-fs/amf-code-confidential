---
layout: post
title: A bug in kestrel
tags: [journeys, oss-guide]
---

In the next chapter of my OSS journey, I will review my latest PR, which fixes a bug in [Kestrel](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/servers/kestrel?view=aspnetcore-10.0){:target="blank" rel="noopener"} web server. Embracing bugs is often the best strategy for an engineer to deepen their knowledge.

## Switching focus

In recent months, I felt a little overwhelmed. Some of my contributions did not gain traction, so I began looking for a more active project where I knew things would move at a healthier pace. [ASP.NET Core](https://dotnet.microsoft.com/pt-br/apps/aspnet){:target="blank" rel="noopener"} emerged as a perfect alternative. Any .NET developer on the web uses this framework, and the community is active and, so far, welcoming.

The codebase is huge, and the best strategy was to focus on a particular area of the framework. Security is one of the aspects of software that has always caught my attention. In recent articles, I documented my contribution to a crypto library. That was satisfying work, but I soon realized that cryptography would be too specialized for my taste.

I prefer to work on something that combines several techniques. A web server such as Kestrel is a sweet spot because it brings together security, networking, parallelism, performance, and more.

While checking the list of open issues, I found [this one](https://github.com/dotnet/aspnetcore/issues/68371){:target="blank" rel="noopener"}, which felt like a beautiful starting point.

## A man is not an island

One of my past mistakes was keeping my head down and focusing on the keyboard without a broader perspective or interaction. My first attitude was to make sure I understood the ticket and to align my approach with the maintainer. The goal was a healthy, small interaction that would help me get to know people and build connections.

The first step was to clone the repo, build it, and run the tests. The README files provide clear guidance, since the framework is huge; loading all modules from the root is simply counterproductive.

The next step was analysis. The maintainer had provided useful information in the ticket, and the code was not that hard to figure out. Still, I had to confirm my gut. Follow the discussion [here](https://github.com/dotnet/aspnetcore/issues/68371){:target="blank" rel="noopener"}. I think this is a good example of community interaction.

## Bug summary

The issue was in Kestrel’s HTTP implementation. When the server received newline characters in [trailers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Trailer){:target="blank" rel="noopener"} and HPACK [Dynamic table](https://httpwg.org/specs/rfc7541.html#dynamic.table){:target="blank" rel="noopener"} retrieval, the values were not rejected, which meant the server was not compliant with [RFC 7540 10.3](https://www.rfc-editor.org/rfc/rfc7540.html#section-10.3){:target="blank" rel="noopener"}.

The validation was already present in the code, but for those paths it had been turn off. The approach was turn it back on and write regression tests. Those tests became more challenging than the bug fix itself, forcing me go into the bones of the HTTP protocol and HPACK. 

Later, I will explore each test and the concepts behind them. For now, here is the bug fix:

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

Trailer headers are a common feature across all HTTP versions, so I had to guarantee that the behavior was correct in all of them. For HTTP/3, I had to write a brand-new test at the stream level. That was not a challenge, though.

I used the test high-level API maintained by the team in the base classes. By following the existing test patterns, it is possible to come up with similar ones. I will paste a snippet below without much detail, and then we can focus on HTTP/2, where the challenge was greater.

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

The test above as mentioned is straightforward: we send the required headers to the server such as: method, path and scheme; while the connection is initialized, and we do not close the stream. Next we send the headers closing the stream, so the server identifies it as trailers. Finally, we wait for the correct error specified in RFC: "Malformed Request".

Regarding HTTP/2, the test was already available; I just had to extend the test data. That sounded like low-effort task, but turned into a quest of learning.

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
I extended IllegalTrailerData adding three new scenarios, ran the test to make sure it would fail, and then patched the fix (TDD approach).

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
The test body itself is quite simple, and the test API makes it easy to understand without digging too deeply. In short, it initialize a new HttpConnection within an application, which are instantiated in the base class to cover various scenarios. An app is anything that can process an HTTP request. 

After stablish a connection, I can use existing APIs to exchange data with the application. In the case of trailers, the stream needs to end along with headers. Finally, the test waits for the error to be returned. Remember: this is a web server, so request are processed in a async loop, which is why the wait seems necessary.

Now the fun part: pay attention to the test data how the bytes are assembled. This is where HPACK matters, let me explain the basics.

### HPACK

The way HTTP/1 and HTTP/2 transfer data had drastically changed from the old text-based protocol. Human readability is a great advantage of text protocols, but, as with everything in computer science, the convenience carries trade-offs. For machines pure text can be error-prone and miss interpreted. 

Let's take this bug as an example. In HTTP/2 carriage return and line feed are just arbitrary data without any special meaning, but when we downgrade to HTTP/1 (common scenario working with legacy applications) the same characters are treated as end-of-line markers. That lead to [HTTP smuggling](https://geniwazir.medium.com/understanding-request-smuggling-a-deep-dive-into-http-exploits-06bc28b0358c){:target="blank" rel="noopener"} and [HTTP Splitting](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling/){:target="blank" rel="noopener"}, both well known exploits.

A binary protocol is, by design more constrained. The same characters do not have the same meaning, and performance can be improved. This makes sense, for something which is the backbone of the web communication. Another advantage of the binary approach is that repeated headers can be compressed efficiently. Since the protocol is stateless client and server often send same header key value pair in each request. This where HPACK helps us.

At the end of the article I will include links worth reading. In short, the client and server maintain a dictionary per connection scope; this dictionary already contain static data, such as common header names and values like path, method and content-encoding. If the header is not in the list, such as ***"x-test-header : testValue"***, it gets added to the dynamic table.

For this particular test, I had to craft the bytes myself. The encoder converts everything to lower case, and some scenarios are sensitive to that conversion, which makes a not viable option. 

Let's analyze the package below:

```csharp
new byte[]{0x00, 0x0B}.Concat(Encoding.ASCII.GetBytes("contains-cr")).Concat(new byte[]{0x01, 0x0D}).ToArray(),
```
the first byte, ***"0x00"***, tells the decoder this package is a ***"Literal Header Field without Indexing"***. The ***"0x0B"*** is the length of the payload name, ***"contains-cr"***. I am using the ASCII encoding as a helper to keep readability. 

The next part is the length of the content payload ***"0x01"*** (just one byte) followed by the value itself. In this case, the value is "CR" represented by the byte ***"0x0D"***.

The following two test cases same logic: HPACK prefix + name length + name payload + value Length + value payload.

## Asking for help

At this point, I was fairly confident that I could submit my PR for review. The maintainer spotted a gap in my understanding. One of the tests that I wrote was not exercising the HPACK dynamic table retrieval path. I had assumed that the table was indexed by name only, so sending TestHeader: initialValue and later TestHeader: \n would suffice.

HPACK indexes names and values separately. In this case, the second entry is treated as a new entry, so it does not reach the HeaderType.Dynamic path in OnHeaderCore.

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
The missing piece was to reproduce this part of the code when the static index is null, and that required a different test setup.

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

I debugged the test to confirm it. After spending hours and days researching, I had to admit that I could not figure it out on my own. To some extent, I understood the issue, but not enough to be confident that my approach would be the most appropriate one.

To get to the line I wanted, the entry point would be `OnDynamicHeaderIndex`, which is a kind of event handler for indexed headers emitted by the HPACK decoder implementation.

The decoder exposes a test seam that allows the injection of a dynamic table. My idea was to prepare a poisoned table with bad values and then call the event.

I tried once without much success. The Http2Connection class owns a private decoder instance, making it impossible to proceed. I would have needed to add another test seam at the HttpConnection level in order to work with a bad decoder. I do not agree with changing production code design just for the sake of tests.

I explored the method by calling the event to inspect the internal behavior and found a debug assertion: `Debug.Assert(_currentHeadersStream != null);`. It meant that if I did not have a current stream open, the state was considered invalid. At that point, I had run out of options, and it was time to ask for help.

I replied in the same thread with what I had tried and what I believed could be a potential solution. The maintainer’s reply did not come instantly, which is normal in the OSS world, but the collaboration was genuinely appreciated.

Below is the test we were looking for:

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

The missing piece was how to keep an active stream alive. This line did the job:

```csharp
    // Start a request header block without END_HEADERS so the connection has an active stream receiving headers.
    await SendHeadersAsync(streamId: 1, flags: Http2HeadersFrameFlags.END_STREAM, headers: _browserRequestHeaders);
```

I did not send the END_HEADERS flag, so the server kept waiting for more header frames, likely a continuation. That meant I could call `OnDynamicIndexedHeader` without hit the debug assertion, pass newline characters, and finally exercise the change.

## Wrapping up

It is mundane work that makes us better engineers. Looking at how a bug can be a perfect opportunity to learn and grow is genuinely enjoyable.

We see the importance of stay humble. No matter how veteran you are, you can always learn by admitting your weaknesses and asking for help when necessary.

Stay present. By paying attention to my knowledge gaps, I was pushed to go deeper. I spent hours revisiting papers and documentation.

With the current state of LLMs, code is no longer the bottleneck. This type of knowledge will be the differentiator, and you need to combine computer science theory with domain expertise.

By sharpening my foundations, I can navigate confidently across these domains. That is one of the reasons OSS hooked me: it gives me the opportunity to contribute to the backbone of the web.

Below are some links worth reading that helped me refresh my knowledge:

[HTTP 2 Explained](https://http2-explained.haxx.se){:target="blank" rel="noopener"}
[HTTP 3 Explained](https://http3-explained.haxx.se/){:target="blank" rel="noopener"}
[HPACK: Header Compression format for HTTP/2](https://medium.com/geekculture/hpack-header-compression-format-for-http-2-155a0b4934f7){:target="blank" rel="noopener"}



