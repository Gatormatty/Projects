// K.E.Y. GUI prototype — C++17 and wxWidgets.
// Build: c++ -std=c++17 gui.cpp $(wx-config --cxxflags --libs) -o key_gui
// This prototype keeps accounts, passwords, and file bytes IN MEMORY ONLY.
// Closing the application discards them. It is not an encrypted storage backend.
// SQLite integration: replace AccountStore with a persistent repository. Use a
// stable account ID as files.owner_id, scope EVERY query to the authenticated
// account ID, and use a vetted salted password KDF (never persist passwords).
#include <wx/wx.h>
#include <wx/file.h>
#include <wx/filename.h>
#include <wx/simplebook.h>
#include <wx/secretstore.h>
#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>
#include <cassert>

namespace key {
using AccountId = std::uint64_t;
constexpr size_t FileLimit = 25 * 1024 * 1024;
constexpr size_t TotalLimit = 100 * 1024 * 1024;

wxString NormalizeUsername(wxString name) {
    return name.Trim(true).Trim(false).Lower();
}
wxString UsernameError(const wxString& name) {
    if (name.empty() || name.length() > 32)
        return "Use a username between 1 and 32 characters.";
    for (auto c : name)
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-'))
            return "Use letters, numbers, underscores, or hyphens in your username.";
    return {};
}
wxString PasswordError(const wxString& password) {
    bool capital = false, special = false;
    const wxString punctuation = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
    for (auto c : password) {
        capital = capital || (c >= 'A' && c <= 'Z');
        special = special || punctuation.Find(c) != wxNOT_FOUND;
    }
    if (password.length() < 8 || !capital || !special)
        return "Try again: use at least 8 characters, one capital letter (A-Z),\n"
               "and one special character, such as !, @, #, or $.";
    return {};
}
struct StoredFile {
    wxString name;
    std::vector<unsigned char> bytes;
};
struct Account {
    AccountId id;
    wxString username;
    // Temporary memory-only secret. This is NOT a database password hash.
    wxSecretValue password;
    bool fingerprintRequested;
    std::vector<StoredFile> files;
};
class AccountStore {
    std::map<AccountId, Account> accounts;
    AccountId nextId = 1;
public:
    bool HasUsername(const wxString& username) const {
        for (const auto& entry : accounts)
            if (entry.second.username == NormalizeUsername(username)) return true;
        return false;
    }
    bool Create(wxString username, const wxString& password, bool fingerprint) {
        username = NormalizeUsername(username);
        if (!UsernameError(username).empty() || !PasswordError(password).empty() || HasUsername(username))
            return false;
        const auto id = nextId++;
        accounts.emplace(id, Account{id, username, wxSecretValue(password), fingerprint, {}});
        return true;
    }
    std::optional<AccountId> Authenticate(const wxString& username, const wxString& password) const {
        const wxSecretValue candidate(password);
        for (const auto& entry : accounts)
            if (entry.second.username == NormalizeUsername(username) && entry.second.password == candidate)
                return entry.first;
        return std::nullopt;
    }
    Account& Get(AccountId id) { return accounts.at(id); }
    size_t BytesUsed() const {
        size_t total = 0;
        for (const auto& entry : accounts)
            for (const auto& file : entry.second.files) total += file.bytes.size();
        return total;
    }
};

class CreateAccountDialog : public wxDialog {
    AccountStore& store;
    wxSimplebook* pages;
    wxTextCtrl *username, *password, *confirmation;
    wxCheckBox* fingerprint;
    wxString chosenUsername;
public:
    wxString CreatedUsername() const { return chosenUsername; }
    CreateAccountDialog(wxWindow* parent, AccountStore& repository)
        : wxDialog(parent, wxID_ANY, "Create your K.E.Y. account", wxDefaultPosition, wxSize(520, 440)), store(repository) {
        auto* outer = new wxBoxSizer(wxVERTICAL);
        pages = new wxSimplebook(this);
        auto* first = new wxPanel(pages);
        auto* s = new wxBoxSizer(wxVERTICAL);
        s->Add(new wxStaticText(first, wxID_ANY, "Step 1 — Choose a username"), 0, wxALL, 16);
        s->Add(new wxStaticText(first, wxID_ANY, "1–32 letters, numbers, underscores, or hyphens.\nUsernames are not case-sensitive."), 0, wxLEFT | wxRIGHT | wxBOTTOM, 16);
        username = new wxTextCtrl(first, wxID_ANY);
        s->Add(username, 0, wxEXPAND | wxLEFT | wxRIGHT, 16);
        auto* next = new wxButton(first, wxID_ANY, "Next");
        s->Add(next, 0, wxALL | wxALIGN_RIGHT, 16);
        first->SetSizer(s);
        pages->AddPage(first, "Username");
        auto* second = new wxPanel(pages);
        auto* t = new wxBoxSizer(wxVERTICAL);
        t->Add(new wxStaticText(second, wxID_ANY, "Step 2 — Create your password"), 0, wxALL, 16);
        t->Add(new wxStaticText(second, wxID_ANY, "At least 8 characters, one capital letter (A-Z),\nand one special character (for example ! @ # $)."), 0, wxLEFT | wxRIGHT | wxBOTTOM, 16);
        t->Add(new wxStaticText(second, wxID_ANY, "Password"), 0, wxLEFT, 16);
        password = new wxTextCtrl(second, wxID_ANY, "", wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD);
        t->Add(password, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 16);
        t->Add(new wxStaticText(second, wxID_ANY, "Confirm password"), 0, wxLEFT, 16);
        confirmation = new wxTextCtrl(second, wxID_ANY, "", wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD);
        t->Add(confirmation, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 16);
        fingerprint = new wxCheckBox(second, wxID_ANY, "I want to set up a fingerprint later");
        t->Add(fingerprint, 0, wxLEFT | wxRIGHT | wxBOTTOM, 16);
        auto* buttons = new wxBoxSizer(wxHORIZONTAL);
        auto* back = new wxButton(second, wxID_ANY, "Back");
        auto* create = new wxButton(second, wxID_ANY, "Create account");
        buttons->Add(back); buttons->AddStretchSpacer(); buttons->Add(create);
        t->Add(buttons, 0, wxEXPAND | wxALL, 16);
        second->SetSizer(t); pages->AddPage(second, "Password");
        outer->Add(pages, 1, wxEXPAND);
        outer->Add(CreateButtonSizer(wxCANCEL), 0, wxALIGN_RIGHT | wxALL, 12);
        SetSizer(outer); CentreOnParent();
        next->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
            chosenUsername = NormalizeUsername(username->GetValue());
            auto error = UsernameError(chosenUsername);
            if (error.empty() && store.HasUsername(chosenUsername)) error = "That username is already taken. Choose another.";
            if (!error.empty()) { wxMessageBox(error, "Check username", wxOK | wxICON_WARNING, this); return; }
            pages->SetSelection(1); password->SetFocus();
        });
        back->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { pages->SetSelection(0); });
        create->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
            auto error = PasswordError(password->GetValue());
            if (error.empty() && password->GetValue() != confirmation->GetValue()) error = "Passwords do not match. Try again.";
            if (!error.empty()) {
                wxMessageBox(error, "Check password", wxOK | wxICON_WARNING, this);
                password->Clear(); confirmation->Clear(); password->SetFocus(); return;
            }
            if (!store.Create(chosenUsername, password->GetValue(), fingerprint->GetValue())) {
                wxMessageBox("Unable to create account. Check your username.", "Create account", wxOK | wxICON_WARNING, this); return;
            }
            password->Clear(); confirmation->Clear(); EndModal(wxID_OK);
        });
    }
};

class MainFrame : public wxFrame {
    AccountStore store;
    std::optional<AccountId> currentAccount;
    wxSimplebook* pages;
    wxTextCtrl *username, *password;
    wxButton *homeLogin, *homeCreate;
    wxStaticText *welcome, *fingerprintStatus;
    wxListBox* files;
    Account* Active() { return currentAccount ? &store.Get(*currentAccount) : nullptr; }
    void RefreshFiles() {
        files->Clear();
        if (auto* account = Active())
            for (const auto& file : account->files)
                files->Append(file.name + wxString::Format("  (%llu bytes)", static_cast<unsigned long long>(file.bytes.size())));
    }
    void ImportFiles() {
        auto* account = Active(); if (!account) return;
        wxFileDialog picker(this, "Store files or pictures", "", "", "All files (*.*)|*.*", wxFD_OPEN | wxFD_FILE_MUST_EXIST | wxFD_MULTIPLE);
        if (picker.ShowModal() != wxID_OK) return;
        wxArrayString paths; picker.GetPaths(paths);
        for (const auto& path : paths) {
            wxFile input(path, wxFile::read);
            const auto length = input.IsOpened() ? input.Length() : wxInvalidOffset;
            if (length < 0 || length > static_cast<wxFileOffset>(FileLimit) ||
                store.BytesUsed() + static_cast<size_t>(length) > TotalLimit) {
                wxMessageBox("Could not import " + wxFileName(path).GetFullName() + "\nLimit: 25 MB per file and 100 MB total in this prototype.", "Import failed", wxOK | wxICON_WARNING, this); continue;
            }
            StoredFile file{wxFileName(path).GetFullName(), std::vector<unsigned char>(static_cast<size_t>(length))};
            if (length && input.Read(file.bytes.data(), file.bytes.size()) != static_cast<ssize_t>(file.bytes.size())) {
                wxMessageBox("Could not read the entire file.", "Import failed", wxOK | wxICON_ERROR, this); continue;
            }
            // Files belong to the authenticated account, never a username typed into a path.
            // Duplicate filenames are separate entries and do not overwrite each other.
            account->files.push_back(std::move(file));
        }
        RefreshFiles();
    }
    void ExportFile() {
        auto* account = Active(); const auto index = files->GetSelection();
        if (!account || index == wxNOT_FOUND) return;
        const auto& file = account->files.at(static_cast<size_t>(index));
        wxFileDialog picker(this, "Save a copy", "", file.name, "All files (*.*)|*.*", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
        if (picker.ShowModal() != wxID_OK) return;
        wxFile output(picker.GetPath(), wxFile::write);
        if (!output.IsOpened() || (!file.bytes.empty() && output.Write(file.bytes.data(), file.bytes.size()) != file.bytes.size()) || !output.Close())
            wxMessageBox("Could not save the complete file.", "Export failed", wxOK | wxICON_ERROR, this);
    }
public:
    MainFrame() : wxFrame(nullptr, wxID_ANY, "K.E.Y. — Keyless Entry for You", wxDefaultPosition, wxSize(740, 560)) {
        SetMinSize(wxSize(640, 500));
        const wxColour blue(35, 105, 185);
        SetBackgroundColour(blue);
        auto* root = new wxBoxSizer(wxVERTICAL);
        auto* notice = new wxStaticText(this, wxID_ANY, "Prototype: accounts and files reset when you close the app. Files are not encrypted yet.");
        notice->SetForegroundColour(*wxWHITE);
        root->Add(notice, 0, wxALL, 12);
        pages = new wxSimplebook(this);

        auto* home = new wxPanel(pages); home->SetBackgroundColour(blue);
        auto* h = new wxBoxSizer(wxVERTICAL);
        auto* title = new wxStaticText(home, wxID_ANY,
            "Welcome to K.E.Y.\nYour secure and safe storing system.",
            wxDefaultPosition, wxDefaultSize, wxALIGN_CENTER);
        title->SetForegroundColour(*wxWHITE);
        title->SetFont(title->GetFont().Scaled(1.7).Bold());
        h->AddStretchSpacer(1);
        h->Add(title, 0, wxALIGN_CENTER | wxLEFT | wxRIGHT | wxBOTTOM, 18);
        auto* picturePlaceholder = new wxStaticText(home, wxID_ANY, "Picture goes here",
            wxDefaultPosition, wxSize(300, 150), wxALIGN_CENTER);
        picturePlaceholder->SetBackgroundColour(wxColour(220, 235, 250));
        picturePlaceholder->SetForegroundColour(wxColour(35, 65, 100));
        h->Add(picturePlaceholder, 0, wxALIGN_CENTER | wxALL, 12);
        auto* prompt = new wxStaticText(home, wxID_ANY, "I want to...",
            wxDefaultPosition, wxDefaultSize, wxALIGN_CENTER);
        prompt->SetForegroundColour(*wxWHITE);
        h->Add(prompt, 0, wxALIGN_CENTER | wxALL, 12);
        homeCreate = new wxButton(home, wxID_ANY, "Create account");
        homeLogin = new wxButton(home, wxID_ANY, "Log in");
        h->Add(homeCreate, 0, wxALIGN_CENTER | wxBOTTOM, 10);
        h->Add(homeLogin, 0, wxALIGN_CENTER);
        h->AddStretchSpacer(1);
        home->SetSizer(h); pages->AddPage(home, "Home");

        auto* login = new wxPanel(pages); login->SetBackgroundColour(blue);
        auto* l = new wxBoxSizer(wxVERTICAL);
        auto* loginTitle = new wxStaticText(login, wxID_ANY, "Log in", wxDefaultPosition, wxDefaultSize, wxALIGN_CENTER);
        loginTitle->SetForegroundColour(*wxWHITE);
        loginTitle->SetFont(loginTitle->GetFont().Scaled(1.5).Bold());
        l->AddStretchSpacer(1);
        l->Add(loginTitle, 0, wxALIGN_CENTER | wxBOTTOM, 20);
        auto* usernameLabel = new wxStaticText(login, wxID_ANY, "Username");
        usernameLabel->SetForegroundColour(*wxWHITE);
        l->Add(usernameLabel, 0, wxLEFT, 24);
        username = new wxTextCtrl(login, wxID_ANY); l->Add(username, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 24);
        auto* passwordLabel = new wxStaticText(login, wxID_ANY, "Password");
        passwordLabel->SetForegroundColour(*wxWHITE);
        l->Add(passwordLabel, 0, wxLEFT, 24);
        password = new wxTextCtrl(login, wxID_ANY, "", wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD | wxTE_PROCESS_ENTER);
        l->Add(password, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 24);
        auto* signIn = new wxButton(login, wxID_ANY, "Log in");
        auto* signUp = new wxButton(login, wxID_ANY, "Create account");
        auto* backHome = new wxButton(login, wxID_ANY, "Back");
        l->Add(signIn, 0, wxALIGN_CENTER | wxBOTTOM, 10);
        l->Add(signUp, 0, wxALIGN_CENTER | wxBOTTOM, 10);
        l->Add(backHome, 0, wxALIGN_CENTER);
        l->AddStretchSpacer(1);
        login->SetSizer(l); pages->AddPage(login, "Login");
        auto* dashboard = new wxPanel(pages); auto* d = new wxBoxSizer(wxVERTICAL);
        welcome = new wxStaticText(dashboard, wxID_ANY, "Your files");
        welcome->SetFont(welcome->GetFont().Scaled(1.4).Bold()); d->Add(welcome, 0, wxALL, 16);
        fingerprintStatus = new wxStaticText(dashboard, wxID_ANY, ""); d->Add(fingerprintStatus, 0, wxLEFT | wxRIGHT | wxBOTTOM, 16);
        files = new wxListBox(dashboard, wxID_ANY); d->Add(files, 1, wxEXPAND | wxLEFT | wxRIGHT, 16);
        auto* actions = new wxBoxSizer(wxHORIZONTAL);
        auto* add = new wxButton(dashboard, wxID_ANY, "Store files / pictures");
        auto* save = new wxButton(dashboard, wxID_ANY, "Save selected copy");
        auto* logout = new wxButton(dashboard, wxID_ANY, "Log out");
        actions->Add(add, 0, wxRIGHT, 8); actions->Add(save); actions->AddStretchSpacer(); actions->Add(logout);
        d->Add(actions, 0, wxEXPAND | wxALL, 16); dashboard->SetSizer(d); pages->AddPage(dashboard, "Files");
        root->Add(pages, 1, wxEXPAND); SetSizer(root); Centre();
        pages->SetSelection(0);
        auto authenticate = [this](wxCommandEvent&) {
            currentAccount = store.Authenticate(username->GetValue(), password->GetValue()); password->Clear();
            if (!currentAccount) { wxMessageBox("Incorrect username or password. Try again.", "Login failed", wxOK | wxICON_WARNING, this); password->SetFocus(); return; }
            auto& account = store.Get(*currentAccount);
            welcome->SetLabel("Signed in as " + account.username + " — Your files");
            fingerprintStatus->SetLabel(account.fingerprintRequested ? "Fingerprint setup requested — enrollment is not implemented yet." : "Fingerprint setup not requested.");
            RefreshFiles(); pages->SetSelection(2); Layout();
        };
        signIn->Bind(wxEVT_BUTTON, authenticate); password->Bind(wxEVT_TEXT_ENTER, authenticate);
        homeLogin->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { pages->SetSelection(1); username->SetFocus(); });
        homeCreate->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
            CreateAccountDialog dialog(this, store);
            if (dialog.ShowModal() == wxID_OK) {
                username->SetValue(dialog.CreatedUsername());
                pages->SetSelection(1);
                password->SetFocus();
                wxMessageBox("Account created. Log in with your username and password.", "Account created", wxOK | wxICON_INFORMATION, this);
            }
        });
        backHome->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { password->Clear(); pages->SetSelection(0); });
        signUp->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
            password->Clear(); CreateAccountDialog dialog(this, store);
            if (dialog.ShowModal() == wxID_OK) {
                username->SetValue(dialog.CreatedUsername());
                wxMessageBox("Account created. Log in with your username and password.", "Account created", wxOK | wxICON_INFORMATION, this);
                password->SetFocus();
            }
        });
        add->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { ImportFiles(); });
        save->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { ExportFile(); });
        logout->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
            currentAccount.reset(); files->Clear(); welcome->SetLabel("Your files"); fingerprintStatus->SetLabel("");
            username->Clear(); password->Clear(); pages->SetSelection(0); username->SetFocus();
        });
        Bind(wxEVT_CLOSE_WINDOW, [this](wxCloseEvent& event) {
            if (event.CanVeto() && wxMessageBox("Closing clears every prototype account and imported file.\nHave you saved any copies you need?", "Close K.E.Y.?", wxYES_NO | wxNO_DEFAULT | wxICON_WARNING, this) != wxYES) { event.Veto(); return; }
            event.Skip();
        });
    }
};
} // namespace key

#ifndef KEY_SELF_TEST
class MyApp : public wxApp {
public:
    bool OnInit() override { (new key::MainFrame())->Show(); return true; }
};
wxIMPLEMENT_APP(MyApp);
#else
int main() {
    using namespace key;
    assert(!PasswordError("Abcdef!").empty());
    assert(!PasswordError("abcdefgh!").empty());
    assert(!PasswordError("Abcdefgh").empty());
    assert(!PasswordError("Abcdefg ").empty());
    assert(PasswordError("Abcdefg!").empty());
    AccountStore store;
    assert(store.Create(" Alice ", "Abcdefg!", true));
    assert(!store.Create("ALICE", "Abcdefg!", false));
    assert(!store.Create("../bob", "Abcdefg!", false));
    assert(!store.Create("bob", "weak", false));
    assert(store.Create("bob", "Different!", false));
    assert(!store.Authenticate("alice", "incorrect"));
    assert(!store.Authenticate("missing", "Abcdefg!"));
    auto alice = store.Authenticate("ALICE", "Abcdefg!");
    auto bob = store.Authenticate("bob", "Different!");
    assert(alice && bob && alice != bob);
    store.Get(*alice).files.push_back({"photo.png", {1, 2, 3}});
    assert(store.Get(*bob).files.empty());
    store.Get(*bob).files.push_back({"photo.png", {9}});
    assert(store.Get(*alice).files[0].bytes == std::vector<unsigned char>({1, 2, 3}));
    assert(store.Get(*alice).fingerprintRequested && !store.Get(*bob).fingerprintRequested);
    assert(store.BytesUsed() == 4);
    return 0;
}
#endif
