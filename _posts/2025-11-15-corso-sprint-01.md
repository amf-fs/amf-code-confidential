---
layout: post
title: Corso! Sprint 01
tags: [journeys, Corso!]
---

This is the continuation of the [Corso! the journey begins]({{'/2025/10/26/corso-journey-begins' | relative_url}}), showcasing the results of the first sprint.

### Architecture Decisions

I agree with the definition of architecture from [Software Architecture: The Hard Parts](https://www.amazon.com/Software-Architecture-Trade-Off-Distributed-Architectures/dp/1492086894). The author says: *"Architecture is everything that you cannot google."* You reach a certain level of seniority when you understand there's no right or wrong, only trade-offs to maximize software quality within budget and timeline constraints. 

If you're stuck on a specific technology or framework, you're not yet an engineer. You're just protecting knowledge you're afraid to lose. True engineers master underlying concepts and apply them across languages and frameworks.

##### Context is Everything

Web development decisions depend heavily on context:
- What hardware can you leverage? (Web a lot)
- What's your team trained in?
- Team size? Budget? Deadline?
- Greenfield or legacy migration?

Most C-level executives and architects overlook these questions. They see greenfield projects as opportunities to implement their weekend TED talks, frustrating both tech teams and business stakeholders.

**Corso's context:** Solo engineer building something useful for daily use, balancing speed, skill showcase, and practicality.

#### Deciding the Tech Stack

Observing my 1Password usage: 70% laptop, 30% phone. I needed desktop and mobile availability. I work on Windows and Linux maintaining native apps for each platform would be too much for a solo dev.

Instead, I chose web first. A web platform lets me showcase skills and ship faster. Angular wasn't special (Blazor or any traditional web stack would work), but context matters. I'm trading off SPA bundle size for delivery speed(because I'm trained) in a 2-week sprint.

**Backend:** .NET was a natural choice. Any server-side tech would work, but I've used .NET for 12+ years and want to continue. .NET hosting has improved but Docker simplifies deployment.

**Storage:** This is where I wanted to explore fundamentals. Instead of PostgreSQL or MSSQL, I'm storing encrypted accounts in files, the same strategy KeePass uses. Databases offer scalability I don't need as a solo user. This choice simplifies setup and showcases encryption handling.

![corso-arch]({{'/assets/images/corso-sprint-01/corso-arch.drawio.svg' | relative_url}})

### The Frontend

**Tech Stack**

- Angular 19
- Typescript 5.5
- Reactive Forms
- Standalone components
- Signals
- Tailwind
- Angular material 19
- RxJS 7.8

I explored two key Angular features: **standalone components** and **signals API**.

**Standalone Components**

Standalone components are the right choice for early-phase apps. No need for feature modules or app.module.ts declarations, development is lighter and faster. Components clearly declare their dependencies, and you only use feature modules when the app grows and needs lazy loading.

```typescript
import { Component, computed, EventEmitter, input, Output, signal, ViewChild } from '@angular/core';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { Account } from '../../app.model';
import { MatListModule, MatSelectionList } from '@angular/material/list';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-account-list',
  //standalone flag
  standalone: true,
  imports: [
    //dependencies
    MatFormFieldModule,
    MatInputModule,
    MatIconModule,
    MatListModule,
    FormsModule
  ],
  templateUrl: './account-list.component.html',
  styleUrl: './account-list.component.scss'
})
export class AccountListComponent {
  // ...
}
```

Benefits: better tree-shaking, smaller bundles, faster first app download.

| Feature | Standalone | NgModules |
|---------|-----------|-----------|
| Setup time | Fast (~2 min) | Slower (module wiring) |
| Bundle size | Smaller (tree-shake unused) | Larger |
| Imports | Self-contained in component | Centralized in module |

**Signals & State Management**

Signals are the future of state management. I decided to start as simply as possible: **centralize all state in the parent component**, making children stateless.

```typescript
export class AccountListComponent {
  @ViewChild(MatSelectionList) selectionList!: MatSelectionList;
  @Output() accountSelectionChanged = new EventEmitter<Account>();

  accounts = input<Account[]>([]);
  private readonly searchTerm = signal<string>('');

  // Derived state: automatically updates when dependencies change
  filteredAccounts = computed(() => {
    const search = this.searchTerm().toLowerCase().trim();
    if (!search) return this.accounts();
    return this.accounts().filter(account =>
      account.name.toLowerCase().includes(search)
    );
  });

  onSearchInput({ target }: Event): void {
    this.searchTerm.set((target as HTMLInputElement).value);
  }

  onAccountListSelectionChange(): void {
    this.accountSelectionChanged.emit(this.selectedAccounts[0]);
  }

  clearSelection(): void {
    this.selectionList.deselectAll();
  }

  private filterBySearchTerm(): Account[] {
    const search = this.searchTerm().toLowerCase().trim();
    if (!search) return this.accounts();
    return this.accounts().filter(account =>
      account.name.toLowerCase().includes(search));
  }
}
```

The `computed()` function is reactive. It re-evaluates only when dependencies change. Templates update automatically:

```html
<mat-list>
  @for (account of filteredAccounts(); track account.id) {
    <mat-list-item>{{ account.name }}</mat-list-item>
  }
</mat-list>
```

**State Management Trade-offs:**

| Aspect | Parent State (Signals) | NgRx Store |
|--------|----------------------|-----------|
| Setup time | ~5 minutes | ~30 minutes (actions, reducers, selectors) |
| Prop drilling | Tedious for deep trees | ✅ Eliminated |
| Component reusability | Limited (state logic tied to parent) | ✅ Full (components are pure) |
| Performance | ✅ Fine-grained tracking | ✅ Normalized store |
| Team velocity | ✅ Fast | ❌ Slower (boilerplate) |

**Why this choice?**

- **Prop drilling:** Passing state down requires repetition, but it's acceptable for Sprint 1.
- **Reusability:** If child components need reuse elsewhere, state logic isn't portable. Acceptable tradeoff now.
- **Speed:** Simple parent state is fast to build. I've seen simple apps bloated with NgRx for no reason over-engineering and the Hype kills team velocity.

NgRx has a place in larger apps with many unrelated components. But it comes at a cost: Redux patterns require many files per feature, slowing teams down.

**The signals API was the missing piece.** It reminded me of React (especially effects handling). Now I have immutable, reactive state without RxJS Observable boilerplate or NgRx overhead. Performance also improves: signals are fine-grained, so Angular tracks exactly what changed no unnecessary component checks.

**UI & Styling**

For UI and styling, I chose Tailwind and Angular Material to boost productivity and focus on exploring other key features. Both helped ship a polished look and feel with minimal effort.

However, Tailwind is still questionable. I caught myself writing lots of class names, making templates verbose for a simple app. The utility-first approach has merit for large design systems, but for Corso's scope, it feels like overkill.

I'll keep Tailwind through Sprint 1 and evaluate after. If verbosity continues, I'll migrate to raw CSS. Starting small and iterating is key, premature optimization or framework adoption kills momentum.

### The backend

**Tech Stack**

  - NET 9.0
  - C# 13
  - ASP.NET Core

The backend main exploration was the encrypted file storage, along with simple clean architecture, the component is all in one but still extensible. At first hand I decided not to create libraries, instead the modules separation occurs through folders and namespace, I would like to demonstrate how the architecture will evolve from day 1, without premature over-engineering.

The app is structured into layers:
  
- **Controllers** — Handle HTTP requests and orchestrate workflows (application services in DDD terms)
- **Core** — Contains business objects (Account entity). For now, it's CRUD-focused with minimal business logic
- **Infrastructure** — Handles data persistence, encryption, and third-party integrations. Acts as an anti-corruption layer, keeping low-level concerns away from business logic and application.

**Encrypted File Storage: Building a Vault**

Instead of a traditional database, I chose to store encrypted accounts in files, the same strategy KeePass uses. Databases offer horizontal scalability and complex queries I don't need it now. File storage is simpler to set up, easier to backup, and lets me explore encryption fundamentals hands-on.

The design is straightforward: a user-defined master password encrypts account data and persists it to disk. I implemented a **unit-of-work pattern** called `AccountsVault`. All mutations (add, update) happen in-memory and are tracked. When you lock the vault, changes are persisted and encrypted atomically committing the transaction in one write.

**Key Derivation: From Password to Encryption Key**

The first operation after creating a vault is unlocking it with your master password. But here's the critical part: **we never use the raw password directly**. Instead, we derive a cryptographic key using a key derivation function (KDF).

Initially, I considered PBKDF2 (the traditional choice), but research led me to **Argon2**, the winner of the Password Hashing Competition in 2015. Argon2 is significantly stronger than PBKDF2 because it's resistant to GPU and ASIC attacks attackers can't parallelize the computation as easily.

Why this matters: A KDF makes brute-force attacks prohibitively expensive. When an attacker attempts to guess your password, they must compute the full KDF for each candidate. Since Argon2 is intentionally slow (configurable iterations and memory usage), deriving a single key might take 100ms on your machine. For an attacker to try 1 million passwords, that's 100,000 seconds—roughly 27 hours. With a strong password, the odds are effectively impossible.

This is why KDFs are perfect for secrets (small data like passwords) but terrible for hashing entire datastores. The overhead compounds quickly with large volumes.

```csharp
private byte[] DeriveKeyFromPassword()
{
    using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(masterPassword));
    argon2.Salt = Encoding.UTF8.GetBytes(salt);
    argon2.DegreeOfParallelism = Environment.ProcessorCount;
    argon2.Iterations = 4;
    argon2.MemorySize = 65536; // 64MB
    return argon2.GetBytes(32); // 32 bytes = 256-bit key for AES
}
```

**Salt: Defense Against Rainbow Tables**

The salt is a random value mixed with the password before key derivation. It defends against rainbow table attacks, where an attacker possesses a massive pre-computed list of hashes and attempts to match them directly.

Without salt, two users with the same password would derive identical keys. An attacker who compromises one vault could instantly compromise all vaults with the same master password. Salt prevents this by adding randomness: even identical passwords produce different keys.

**AES-256: Symmetric Encryption**

Once we have the derived key, we encrypt account data using AES-256, a symmetric algorithm. AES stands for Advanced Encryption Standard, and it's the gold standard for data encryption. Unlike asymmetric encryption (public/private key pairs), symmetric encryption uses a single shared key for both encryption and decryption. For a personal vault with one user, symmetric encryption is ideal.

The encryption happens in-memory during the lock operation:

```csharp
public async Task LockAsync()
{
    using var fileStream = File.Create(filePath);
    using var aes = Aes.Create();
    aes.Key = encryptionKey;
    aes.GenerateIV();

    // Write IV to the beginning of the file
    await fileStream.WriteAsync(aes.IV.AsMemory(0, aes.IV.Length));

    using var cryptoStream = new CryptoStream(fileStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
    using var writer = new StreamWriter(cryptoStream, Encoding.UTF8);

    var json = JsonSerializer.Serialize(accounts, new JsonSerializerOptions { WriteIndented = true });
    await writer.WriteAsync(json);
}
```

**Initialization Vector: Ensuring Randomness in Ciphertext**

Here's a subtle but critical detail: every time you lock the vault, AES generates a new random Initialization Vector (IV). The IV ensures that encrypting the same plaintext with the same key produces different cipher texts.

Without an IV, pattern analysis becomes possible. If an attacker sees two identical cipher texts, they know the plaintext hasn't changed. Over time, this leaks information. The IV randomizes the encryption process, making the cipher text unpredictable even for identical inputs.

The IV is stored in plaintext at the first 16 bytes of the encrypted file. This is standard practice the IV doesn't need to be secret, only random and unique per encryption operation:

```csharp
// During decryption, extract the IV from the file
var iv = new byte[16];
await fileStream.ReadExactlyAsync(iv);
aes.IV = iv;
```

**JSON Serialization: A Pragmatic Trade-off**

Accounts are serialized to JSON before encryption. JSON is lightweight, human-readable, and has native .NET support. The trade-off: JSON is still somewhat readable (compared to binary formats), but encryption makes this irrelevant. An attacker with encrypted data can't parse JSON anyway.

For future versions, I could switch to a binary format like Protocol Buffers or MessagePack for slightly better performance and compressibility. For Sprint 1, JSON strikes the right balance between simplicity and efficiency.

**The Unit-of-Work Pattern**

All mutations are tracked in-memory until you explicitly lock the vault. This means:

```csharp
public void Add(Account @new)
{
    @new.Id = accounts.Count == 0 ? 1 : accounts.Max(_ => _.Id) + 1;
    accounts.Add(@new);
}

public void Update(Account newValues)
{
    var target = accounts.SingleOrDefault(_ => _.Id == newValues.Id) 
        ?? throw new InvalidOperationException($"account with id : {newValues.Id} was not found");
    target.Name = newValues.Name;
    target.Username = newValues.Username;
    target.Password = newValues.Password;
}
```

Changes accumulate in memory. If the application crashes before locking, no data persists. This is acceptable for Corso because the web UI keeps the vault locked most of the time. When you make changes, they're staged until you explicitly lock the vault again at which point they're encrypted and written atomically.

**The Full Implementation**

```csharp
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CorsoApi.Core;
using Konscious.Security.Cryptography;

namespace CorsoApi.Infrastructure
{
    public interface IAccountsVault
    {
        void Add(Account @new);
        bool Exists(int id);
        List<Account> GetAll();
        Task LockAsync();
        Task UnLockAsync();
        void Update(Account newValues);
    }

    public class AccountsVault : IAccountsVault
    {
        private List<Account> accounts;
        private readonly string filePath;
        private readonly string masterPassword;
        private readonly string salt;
        private byte[] encryptionKey;

        public AccountsVault(string filePath, string masterPassword, string salt)
        {
            this.filePath = filePath;
            this.masterPassword = masterPassword;
            this.salt = salt;
            accounts = [];
            encryptionKey = [];
        }

        public List<Account> GetAll()
        {
            return accounts;
        }

        public void Add(Account @new)
        {
            @new.Id = accounts.Count == 0 ? 1 : accounts.Max(_ => _.Id) + 1;
            accounts.Add(@new);
        }

        public bool Exists(int id) =>
            accounts.Any(_ => id == _.Id);

        public async Task LockAsync()
        {
            using var fileStream = File.Create(filePath);
            using var aes = Aes.Create();
            aes.Key = encryptionKey;
            aes.GenerateIV();

            // Write IV to beginning of file
            await fileStream.WriteAsync(aes.IV.AsMemory(0, aes.IV.Length));

            using var cryptoStream = new CryptoStream(fileStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
            using var writer = new StreamWriter(cryptoStream, Encoding.UTF8);

            var json = JsonSerializer.Serialize(accounts, new JsonSerializerOptions { WriteIndented = true });
            await writer.WriteAsync(json);
        }

        public void Update(Account newValues)
        {
            var target = accounts.SingleOrDefault(_ => _.Id == newValues.Id) 
                ?? throw new InvalidOperationException($"account with id : {newValues.Id} was not found");
            target.Name = newValues.Name;
            target.Username = newValues.Username;
            target.Password = newValues.Password;
        }

        public async Task UnLockAsync()
        {
            encryptionKey = DeriveKeyFromPassword();
            accounts = await LoadAsync();
        }

        private async Task<List<Account>> LoadAsync()
        {
            if (!File.Exists(filePath))
            {
                return [];
            }

            using var fileStream = File.OpenRead(filePath);
            using var aes = Aes.Create();
            aes.Key = encryptionKey;

            var iv = new byte[16];
            await fileStream.ReadExactlyAsync(iv);
            aes.IV = iv;

            using var cryptoStream = new CryptoStream(fileStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
            using var reader = new StreamReader(cryptoStream, Encoding.UTF8);
            var json = await reader.ReadToEndAsync();
            return JsonSerializer.Deserialize<List<Account>>(json) ?? [];
        }

        private byte[] DeriveKeyFromPassword()
        {
            using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(masterPassword));
            argon2.Salt = Encoding.UTF8.GetBytes(salt);
            argon2.DegreeOfParallelism = Environment.ProcessorCount;
            argon2.Iterations = 4;
            argon2.MemorySize = 65536; // 64MB
            return argon2.GetBytes(32);
        }
    }
}
```
**Caveats**

- The vault was injected as singleton because of caching but is not thread safe, acceptable for a solo use, might be a problem for concurrent users (we may explore it in future)
- Local caching makes the vault not scalable horizontally Redis could be an alternative to tackle this issue.
- There is no cache eviction policy, so the vault will accumulate decrypted accounts in memory indefinitely. For Sprint 1 with a solo user and a small account count, this is acceptable. If Corso scales to hundreds of accounts, implementing a size threshold or LRU eviction policy would become necessary. (implementing our own caching solution could be interesting)

**Storing secrets**

We have a encrypted vault to store our accounts all good so far, the last piece of this puzzle is how I can safely store my master password and salt. In future we will ask user to provide the master password, however to fit the deadline I'll not implement this feature rather I would store this as app secret using some OS level tool. Usually cloud providers offer some Vault feature to hold our secrets safely, but Corso! still a baby, and I am not sure about his home. I am providing an abstraction, so it keeps the possibilities open.

````csharp

namespace CorsoApi.Infrastructure;

/// <summary>
/// Abstraction for a secret store (e.g. Azure Key Vault, AWS Secrets Manager, KeyRing, lib secret).
/// </summary>
public interface ISecretStore
{
    /// <summary>
    /// Retrieves a secret value by key. Returns null if the secret does not exist.
    /// </summary>
    Task<string?> GetSecretAsync(string key, CancellationToken cancellationToken = default);
}
````
Most likely I'll start hosting it in linux server and my local box is also same, the option is keyring a native secret store. I invoke the `secret-tool` CLI to interact with it. 

````csharp
using System.Diagnostics;

namespace CorsoApi.Infrastructure
{
    public class KeyringSecretStore : ISecretStore
    {
        public async Task<string?> GetSecretAsync(string keyName, CancellationToken cancellationToken = default)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "secret-tool",
                Arguments = $"lookup corso {keyName}",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi) ??
                throw new InvalidOperationException("Failed to start secret-tool process.");

            string? output = await process.StandardOutput.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken);
            return output?.Trim();
        }
    }
}
````
The implementation is simple: spawn a `secret-tool` process with a lookup command and capture its output. No complexity, no external NuGet packages, just POSIX interop.

### Sprint 02 - (11-16 to 11-30)

The goal of next, is deploying it somewhere, so I can start using this app on my day to day. To make it safe enough we need to provide some security enhancements.

- The app needs to run over HTTPS
- Api authorization to refuse unwanted connections, here I'll explore if asking the master password as login or whitelist some device connections, whatever fits in a sprint.
- Deployment itself preferable free hosting.

You can find the code on <a href="https://github.com/amf-fs/corso" target="_blank" rel="noopener">GitHub</a>, see ya!