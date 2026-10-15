import {
    AttributeTypeIdentifier,
    CredentialTypeIdentifier,
    IssuerIdentifier,
    IssueWizardIdentifier,
    RequestorIdentifier,
    RequestorSchemeIdentifier,
    SchemeManagerIdentifier,
} from "./identifiers.ts"
import { Timestamp } from "./requests.ts"
import { SchemeManagerIndex, SchemeManagerStatus } from "./schemes.ts"

/**
 * name/namespace pair for an XML element, taken straight from the parsed
 * scheme XML so we can keep track of which element a description came from
 */
type xmlName = {
    name: string
    space: string
}

/**
 * a scheme manager: the top-level container that groups issuers and their
 * credential types, plus all the metadata about where the scheme lives and
 * how it's served (keyshare, timestamp server, etc.)
 */
export class SchemeManager {
    id: string
    name: TranslatedString
    url: string
    contact: string
    demo: boolean
    description: TranslatedString
    minimumAppVersion: SchemeAppVersion
    keyshareServer: string
    keyshareWebsite: string
    keyshareAttribute: string
    timestampServer: string
    languages: string[]
    xmlVersion: number
    xmlName: xmlName

    status: SchemeManagerStatus
    timestamp?: Timestamp

    storagepath: string
    index: SchemeManagerIndex

    /**
     * builds a scheme manager from a partial object, filling in sensible
     * defaults for anything left out so partially-parsed schemes still
     * produce a usable instance
     * @param init partial scheme manager fields
     */
    constructor({
        id = "",
        name = { "": "" },
        url = "",
        contact = "",
        demo = false,
        description = { "": "" },
        minimumAppVersion = { Android: 0, IOS: 0 },
        keyshareServer = "",
        keyshareWebsite = "",
        keyshareAttribute = "",
        timestampServer = "",
        languages = [],
        xmlVersion = 0,
        xmlName = { name: "", space: "" },
        status = "",
        timestamp = undefined,
        storagepath = "",
        index = {},
    }: Partial<SchemeManager>) {
        this.id = id
        this.name = name
        this.url = url
        this.contact = contact
        this.demo = demo
        this.description = description
        this.minimumAppVersion = minimumAppVersion
        this.keyshareServer = keyshareServer
        this.keyshareWebsite = keyshareWebsite
        this.keyshareAttribute = keyshareAttribute
        this.timestampServer = timestampServer
        this.languages = languages
        this.xmlVersion = xmlVersion
        this.xmlName = xmlName
        this.status = status
        this.timestamp = timestamp
        this.storagepath = storagepath
        this.index = index
    }

    /**
     * whether this scheme is distributed, i.e. it relies on a keyshare server.
     * we just check that a keyshare server url was set
     * @returns true if a keyshare server is configured
     */
    public distributed(): boolean {
        return this.keyshareServer.length > 0
    }
}

/**
 * minimum Yivi app version a scheme requires, split per platform so a scheme
 * can demand different minimums on android vs ios
 */
export type SchemeAppVersion = {
    Android: number
    IOS: number
}

/**
 * an issuer within a scheme: the party that hands out credentials, plus its
 * contact details and the scheme it belongs to
 */
export type Issuer = {
    id: string
    name: TranslatedString
    schemeManagerID: string
    contactAddress: string
    contactEMail: string
    deprecatedSince: Timestamp
    languages: string[]
    xmlVersion: number
}

/**
 * a credential type: describes one kind of credential an issuer can hand out,
 * including its attributes, revocation settings, display colours, and the faq
 * text shown in the app
 */
export class CredentialType {
    id: string
    name: TranslatedString
    issuerID: string
    schemeManagerID: string
    isSingleton: boolean
    disallowDelete: boolean
    description: TranslatedString
    attributeTypes?: AttributeType[]
    revocationServers: string[]
    revocationUpdateCount: number
    revocationUpdateSpeed: number
    revocationIndex: number
    languages: string[]
    xmlVersion: number
    xmlName: xmlName

    issueURL: TranslatedString
    isULIssueURL: boolean

    deprecatedSince?: Timestamp

    dependencies?: CredentialDependencies

    foregroundColor: string
    backgroundGradientStart: string
    backgroundGradientEnd: string

    isInCredentialStore: boolean
    category?: TranslatedString
    faqIntro?: TranslatedString
    faqPurpose?: TranslatedString
    faqContent?: TranslatedString
    faqHowTo?: TranslatedString
    faqSummary?: TranslatedString

    /**
     * builds a credential type from a partial object, defaulting every field
     * so a half-filled description still constructs cleanly
     * @param init partial credential type fields
     */
    constructor({
        id = "",
        name = {},
        issuerID = "",
        schemeManagerID = "",
        isSingleton = false,
        disallowDelete = false,
        description = {},
        attributeTypes = [],
        revocationServers = [""],
        revocationUpdateCount = 0,
        revocationUpdateSpeed = 0,
        revocationIndex = 0,
        languages = [""],
        xmlVersion = 0,
        xmlName = { name: "", space: "" },
        issueURL = {},
        isULIssueURL = false,
        deprecatedSince = undefined,
        dependencies = [[[]]],
        foregroundColor = "",
        backgroundGradientStart = "",
        backgroundGradientEnd = "",
        isInCredentialStore = false,
        category = {},
        faqIntro = undefined,
        faqPurpose = undefined,
        faqContent = undefined,
        faqHowTo = undefined,
        faqSummary = undefined,
    }: Partial<CredentialType>) {
        this.id = id
        this.name = name
        this.issuerID = issuerID
        this.schemeManagerID = schemeManagerID
        this.isSingleton = isSingleton
        this.disallowDelete = disallowDelete
        this.description = description
        this.attributeTypes = attributeTypes
        this.revocationServers = revocationServers
        this.revocationUpdateCount = revocationUpdateCount
        this.revocationUpdateSpeed = revocationUpdateSpeed
        this.revocationIndex = revocationIndex
        this.languages = languages
        this.xmlVersion = xmlVersion
        this.xmlName = xmlName
        this.issueURL = issueURL
        this.isULIssueURL = isULIssueURL
        this.deprecatedSince = deprecatedSince
        this.dependencies = dependencies
        this.foregroundColor = foregroundColor
        this.backgroundGradientStart = backgroundGradientStart
        this.backgroundGradientEnd = backgroundGradientEnd
        this.isInCredentialStore = isInCredentialStore
        this.category = category
        this.faqIntro = faqIntro
        this.faqPurpose = faqPurpose
        this.faqContent = faqContent
        this.faqHowTo = faqHowTo
        this.faqSummary = faqSummary
    }

    /**
     * full identifier of this credential type, formatted as
     * "scheme.issuer.credential"
     * @returns the dotted credential type identifier
     */
    public identifier(): CredentialTypeIdentifier {
        return this.schemeManagerID + "." + this.issuerID + "." + this.id
    }

    /**
     * identifier of the issuer this credential belongs to, as "scheme.issuer"
     * @returns the dotted issuer identifier
     */
    public issuerIdentifier(): IssuerIdentifier {
        return this.schemeManagerID + "." + this.issuerID
    }

    /**
     * identifier of the scheme this credential lives in
     * @returns the scheme manager identifier
     */
    public schemeManagerIdentifier(): SchemeManagerIdentifier {
        return this.schemeManagerID
    }
}

/**
 * a single attribute within a credential type, e.g. "fullname" or "over18".
 * carries display hints and its position (index) inside the credential
 */
export class AttributeType {
    id: string
    optional?: string
    name: TranslatedString
    description: TranslatedString

    randomBlind?: boolean

    index: number
    displayIndex?: number
    displayHint?: string

    revocationAttribute?: boolean

    credentialTypeID: string
    issuerID: string
    schemeManagerID: string

    /**
     * builds an attribute type from a partial object, defaulting missing
     * fields. note the index defaults to 0 and the optional flags default to
     * undefined/false rather than being left unset
     * @param init partial attribute type fields
     */
    constructor({
        id = "",
        optional = undefined,
        name = {},
        description = {},
        randomBlind = undefined,
        index = 0,
        displayIndex = undefined,
        displayHint = undefined,
        revocationAttribute = undefined,
        credentialTypeID = "",
        issuerID = "",
        schemeManagerID = "",
    }: Partial<AttributeType>) {
        this.id = id
        this.name = name
        this.description = description
        this.index = index ?? 0
        this.optional = optional
        this.randomBlind = randomBlind ?? false
        this.displayIndex = displayIndex
        this.displayHint = displayHint
        this.revocationAttribute = revocationAttribute
        this.credentialTypeID = credentialTypeID ?? ""
        this.issuerID = issuerID ?? ""
        this.schemeManagerID = schemeManagerID ?? ""
    }

    /**
     * full identifier of this attribute, formatted as
     * "scheme.issuer.credential.attribute"
     * @returns the dotted attribute identifier
     */
    public identifier(): AttributeTypeIdentifier {
        return (
            this.schemeManagerID + "." + this.issuerID + "." + this.credentialTypeID + "." + this.id
        )
    }

    /**
     * identifier of the issuer this attribute's credential belongs to,
     * as "scheme.issuer"
     * @returns the dotted issuer identifier
     */
    public issuerIdentifier(): IssuerIdentifier {
        return this.schemeManagerID + "." + this.issuerID
    }

    /**
     * identifier of the scheme this attribute lives in
     * @returns the scheme manager identifier
     */
    public schemeManagerIdentifier(): SchemeManagerIdentifier {
        return this.schemeManagerID
    }
}

/**
 * which other credential types a credential depends on, expressed as a
 * condiscon (conjunction of disjunctions of conjunctions) of credential
 * identifiers, so the three nested arrays are and-of-or-of-and
 */
export type CredentialDependencies = CredentialTypeIdentifier[][][]

/**
 * a requestor scheme: a scheme listing verified requestors (verifiers) along
 * with the metadata needed to trust and display them
 */
export type RequestorScheme = {
    ID: RequestorSchemeIdentifier
    URL: string
    Demo: boolean
    Languages: string[]
    Status: SchemeManagerStatus
    Timestamp: Timestamp

    storagepath: string
    index: SchemeManagerIndex
    requestors: RequestorInfo[]
}

/**
 * a single verified requestor inside a requestor scheme: who they are, the
 * hostnames they're allowed to use, their logo, and any issue wizards they
 * offer
 */
export type RequestorInfo = {
    ID: RequestorIdentifier
    Scheme: RequestorSchemeIdentifier
    Name: TranslatedString
    Industry: TranslatedString
    Hostnames: string[]
    Logo: string
    LogoPath: string
    ValidUntil: Timestamp
    Unverified: boolean
    Languages: string[]
    Wizards: Map<IssueWizardIdentifier, IssueWizard>
}

/**
 * an issue wizard: a guided, multi-step flow that walks a user through
 * obtaining one or more credentials, with its own branding and faq
 */
export type IssueWizard = {
    ID: IssueWizardIdentifier
    Title: TranslatedString
    Logo: string // sha256 of the logo contents, which doubles as its filename on disk
    LogoPath: string // full path to the logo, filled in while parsing the scheme
    Color: string
    TextColor: string
    Issues: CredentialTypeIdentifier
    AllowOtherRequestors: boolean
    Languages: string[]

    Info: TranslatedString
    FAQ: IssueWizardQA[]

    Intro: TranslatedString
    SuccessHeader: TranslatedString
    SuccessText: TranslatedString
    ExpandDependencies: boolean
    Contents: IssueWizardContents
}

/**
 * a single faq entry shown in an issue wizard: one question and its answer,
 * both translated
 */
type IssueWizardQA = {
    Question: TranslatedString
    Answer: TranslatedString
}

/**
 * the steps that make up an issue wizard, expressed as a condiscon of wizard
 * items so the nesting is and-of-or-of-and
 */
type IssueWizardContents = IssueWizardItem[][][]

/**
 * a single step in an issue wizard. its Type decides whether the step issues
 * a credential, starts a session, or opens a website, so most of the other
 * fields only matter for one of those cases
 */
type IssueWizardItem = {
    Type: IssueWizardItemType
    Credential: CredentialTypeIdentifier
    Header: TranslatedString
    Text: TranslatedString
    Label: TranslatedString
    SessionURL: string
    URL: TranslatedString
    InApp: boolean

    languages: string[]
}

/**
 * the kind of an issue wizard item; in practice one of "credential",
 * "session", or "website", which decides what the step does
 */
type IssueWizardItemType = string

/**
 * a string with one translation per language code, e.g.
 * { "en": "Hello", "nl": "Hallo" }. used everywhere user-facing text needs to
 * be shown in the app's chosen language
 */
export type TranslatedString = Record<string, string>
