package chaincode

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	//"github.com/gofiber/fiber/v2/uuid"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/xeipuuv/gojsonschema"

	"crypto/sha256"
	"encoding/hex"
	"log"
)

// SmartContract provides functions for managing an Asset
type SmartContract struct {
	contractapi.Contract
}

// Asset describes basic details of what makes up a simple asset

// Asset describes basic details of what makes up a simple asset
// Insert struct field in alphabetic order => to achieve determinism across languages
// golang keeps the order when marshal to json but doesn't order automatically

var lastSchemaHash string
var APIUserIds []string

const PDC1 = "PDC1"
const PDC2 = "PDC2"

type Data struct {
	OrgName     string `json:"OrgName"`
	ProjectName string `json:"ProjectName"`
	ContentHash string `json:"ContentHash"`
	Comment     string `json:"Comment"`
	APIUserID   string `json:"APIUserID"`
	Date        string `json:"Date"`
	JsonContent map[string]interface{}
}

type PrivateSchemaContent struct {
	JsonSchemaContent map[string]interface{} `json:"JsonSchemaContent"`
	SchemaId          string                 `json:"SchemaId"`
	Project           string                 `json:"Project`
}

type PrivateProjectsContent struct {
	OrgName     string `json:OrgName`
	ProjectName string `json:ProjectName`
	AdmninGroup []User `json:AdminGroup`
	UsersGroup  []User `json:UsersGroup`
	ProjectID   string `json:ProjectID`
}

// Not being persisted
type Schema struct {
	JsonSchemaContent map[string]interface{} `json:"JsonSchemaContent"`
	SchemaId          string                 `json:"SchemaId"`
	Project           string                 `json:"Project`
}

type User struct {
	UID       string `json:"UID"`
	APIUserId string `json:"APIUserId"`
	Group     string `json:"Group"`
	Project   string `json:"Project"`
	Org       string `json:"Org"`
}

type Group struct {
	GID       string `json:"GID"`
	GroupName string `json:"GroupName"`
	Project   string `json:"Project"`
	Org       string `json:"Org"`
	Users     []User `json:"Users"`
}

type Project struct {
	PID         string  `json:"PID"`
	ProjectName string  `json:"ProjectName"`
	Org         string  `json:"Org"`
	Groups      []Group `json:"Groups"`
}

// Main function
func main() {
	aChaincode, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		log.Panicf("Error creating artifact chaincode: %v", err)
	}

	if err := aChaincode.Start(); err != nil {
		log.Panicf("Error starting artifact chaincode: %v", err)
	}
}

func (s *SmartContract) Hash(ctx contractapi.TransactionContextInterface, doc string) (string, error) {

	var v interface{}
	err := json.Unmarshal([]byte(doc), &v)
	if err != nil {
		return "HASH CRASH", fmt.Errorf("Unable to unmarshal Json String passed as parameter. No hash calculation can be completed: %v", err)
	} else {
		cdoc, err := json.Marshal(v)
		if err != nil {
			return "HASH CRASH", fmt.Errorf("Unable to re-marshal interface into json format. No hash calculation can be completed: %v", err)
		} else {
			sum := sha256.Sum256(cdoc)
			return hex.EncodeToString(sum[0:]), nil
		}
	}
}

func (s *SmartContract) JsonReader(ctx contractapi.TransactionContextInterface, content string) (map[string]interface{}, error) {

	var payload map[string]interface{}
	// Now let's unmarshall the data into `payload`
	err := json.Unmarshal([]byte(content), &payload)
	if err != nil {
		log.Fatal("Error during Unmarshal() of string into type Interface: ", err)
	}
	return payload, nil

}

// GetAllAssets returns all assets found in world state

func (s *SmartContract) GetAllAssets(ctx contractapi.TransactionContextInterface) ([]*Data, error) {
	// range query with empty string for startKey and endKey does an
	// open-ended query of all assets in the chaincode namespace.
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var dataSamples []*Data
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var data map[string]interface{}
		err = json.Unmarshal(queryResponse.Value, &data)
		if err != nil {
			return nil, err
		} else {
			var dataSruct Data
			err = json.Unmarshal(queryResponse.Value, &dataSruct)
			if err != nil {
				return nil, err
			} else {
				dataSamples = append(dataSamples, &dataSruct)
			}
		}
	}

	return dataSamples, nil
}

func (s *SmartContract) SchemaExists(ctx contractapi.TransactionContextInterface, SchemaID string) (bool, error) {

	assetJSON, err := s.ReadSchemaFromPDC(ctx, SchemaID)

	if assetJSON == nil {
		return false, fmt.Errorf("failed to read from world state. Schema doesn't exist: %v", err)
	} else if err != nil {
		return false, fmt.Errorf("failed to read from world state. Schema doesn't exist: %v", err)
	} else {
		return true, nil
	}
}

// AssetExists returns true when asset with given ID exists in world state
func (s *SmartContract) AssetExists(ctx contractapi.TransactionContextInterface, Hash string) (bool, error) {
	assetJSON, err := ctx.GetStub().GetState(Hash)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state. Asset dosen't exist: %v", err)
	} else if assetJSON != nil {
		var data map[string]interface{}
		err2 := json.Unmarshal(assetJSON, &data)
		if err2 != nil {
			return false, fmt.Errorf("failed to read from world state: %v", err2)
		} else if err3, ok := data["ContentHash"]; ok {
			return assetJSON != nil, nil
		} else {
			return false, fmt.Errorf("failed to read from world state. Hash passed as parameter may correspond to a Schema struct rather than to a Data Struct: %v", err3)
		}
	} else {
		return assetJSON != nil, nil
	}
}

// JSON Validation

func (s *SmartContract) ValidJson(ctx contractapi.TransactionContextInterface, JsonContent string, SchemaID string) (bool, error) {

	schema, err := s.ReadSchemaFromPDC(ctx, SchemaID)

	if err != nil {
		panic(err.Error())
	}

	schemaLoader := gojsonschema.NewGoLoader(schema.JsonSchemaContent)
	documentLoader := gojsonschema.NewStringLoader(JsonContent)

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)

	if err != nil {
		panic(err.Error())
	}

	if result.Valid() {
		fmt.Printf("The document is valid\n")
	} else {
		fmt.Printf("The document is not valid. see errors :\n")
		for _, desc := range result.Errors() {
			fmt.Printf("- %s\n", desc)
		}
	}
	return result.Valid(), nil
}

// CreateDataSample issues a new Data Sample to the world state with given details.
func (s *SmartContract) CreateDataSample(ctx contractapi.TransactionContextInterface,
	OrgName string, ProjectName string, Comment string, Date string, APIUserID string, JsonFileContent string, SchemaID string) error {

	SchemaExists, err := s.SchemaExists(ctx, SchemaID)

	if err != nil {
		return err
	}
	if !SchemaExists {
		return fmt.Errorf("the Schema with Id %s doesn't exists", SchemaID)
	}
	ContentHash, err := s.Hash(ctx, JsonFileContent)
	if err != nil {
		return err
	}
	exists, err := s.AssetExists(ctx, ContentHash)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the asset %s already exists", ContentHash)
	}

	valid, err := s.ValidJson(ctx, JsonFileContent, SchemaID)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("the json file provided is not valid")
	} else {
		jsonFileContent, err := s.JsonReader(ctx, JsonFileContent)
		if err != nil {
			return err
		} else {
			data := Data{
				OrgName:     OrgName,
				ProjectName: ProjectName,
				ContentHash: ContentHash,
				Comment:     Comment,
				Date:        Date,
				APIUserID:   APIUserID,
				JsonContent: jsonFileContent,
			}

			assetJSON, err := json.Marshal(data)
			if err != nil {
				return err
			}
			return ctx.GetStub().PutState(ContentHash, assetJSON)
		}
	}

}

func (s *SmartContract) ReadAsset(ctx contractapi.TransactionContextInterface, Id string) (*Data, error) {
	assetJSON, err := ctx.GetStub().GetState(Id)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if assetJSON == nil {
		return nil, fmt.Errorf("the asset %s does not exist", Id)
	}

	var data Data
	err = json.Unmarshal(assetJSON, &data)
	if err != nil {
		return nil, err
	}

	return &data, nil
}

func (s *SmartContract) ReadUser(ctx contractapi.TransactionContextInterface, UUID string) (*User, error) {
	assetJSON, err := ctx.GetStub().GetState(UUID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if assetJSON == nil {
		return nil, fmt.Errorf("the User %s does not exist", UUID)
	}

	var user User
	err = json.Unmarshal(assetJSON, &user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// TransferAsset updates the owner field of asset with given id in world state, and returns the old owner.

func (s *SmartContract) contains(ctx contractapi.TransactionContextInterface, st []string, str string) bool {
	for _, v := range st {
		if v == str {
			return true
		}
	}
	return false
}

func (s *SmartContract) UserExists(ctx contractapi.TransactionContextInterface, APIUserId string) bool {
	return s.contains(ctx, APIUserIds, APIUserId)
}

// Subscribe a new user to the Implicit PDC (APIUserId, Project and Group are parameters in transient map)
func (s *SmartContract) NewUser(ctx contractapi.TransactionContextInterface) error {

	transientAssetJSON, err := s.getTransientMap(ctx)
	if err != nil {
		return fmt.Errorf("error getting transient: %v", err)
	}

	type transientInput struct {
		UID       string `json:"UID"`
		APIUserId string `json:"APIUserId"`
		Group     string `json:"Group"`
		Project   string `json:"Project"`
		Org       string `json:"Org"`
	}

	var assetInput transientInput
	err = json.Unmarshal(transientAssetJSON, &assetInput)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	MSP, err := shim.GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get MSPID: %v", err)
	}
	PDC := "_implicit_org_" + MSP
	assetInput.Org = MSP
	assetInput.UID = MSP + "." + assetInput.Project + "." + assetInput.Group + "." + assetInput.APIUserId
	assetAsBytes, err := ctx.GetStub().GetPrivateData(PDC, assetInput.UID)

	if err != nil {
		return fmt.Errorf("failed to get User: %v", err)
	} else if assetAsBytes != nil {
		fmt.Println("User already exists: " + assetInput.UID)
		return fmt.Errorf("this User already exists: " + assetInput.UID)
	}

	// Get ID of submitting client identity
	clientID, err := submittingClientIdentity(ctx)
	if err != nil {
		return err
	}

	// Verify that the client is submitting request to peer in their organization
	// This is to ensure that a client from another org doesn't attempt to read or
	// write private data from this peer.
	err = verifyClientOrgMatchesPeerOrg(ctx)
	if err != nil {
		return fmt.Errorf("CreateSchema cannot be performed: Error %v", err)
	}

	NewUser := User{
		UID:       assetInput.UID,
		APIUserId: assetInput.APIUserId,
		Group:     assetInput.Group,
		Project:   assetInput.Project,
		Org:       MSP,
	}
	assetJSONasBytes, err := json.Marshal(NewUser)
	if err != nil {
		return fmt.Errorf("failed to marshal Schema into JSON: %v", err)
	}

	// Save asset to private data collection
	// Typical logger, logs to stdout/file in the fabric managed docker container, running this chaincode
	// Look for container name like dev-peer0.org1.example.com-{chaincodename_version}-xyz
	log.Printf("WriteSchemaToPDC Put: collection %v, ID %v, owner %v", PDC, assetInput.UID, clientID)

	err = ctx.GetStub().PutPrivateData(PDC, assetInput.UID, assetJSONasBytes)
	if err != nil {
		return fmt.Errorf("failed to put asset into private data collection: %v", err)
	}

	return nil

}

/**func (s *SmartContract) AssociateUserWithUUID(ctx contractapi.TransactionContextInterface, UUID string, APIId string) (string, error) {
	user, err := s.ReadUser(ctx, UUID)
	if err != nil {
		return "Error", fmt.Errorf("read User function failed excecution: %v", err)
	}
	if s.contains(ctx, user.APIUserId, APIId) {
		return "APIId provided is already associated with user " + UUID, nil
	}
	user.APIUserId = append(user.APIUserId, APIId)

	assetJSON, err := json.Marshal(user)
	if err != nil {
		return "Marshal of Data not done", err
	}

	err = ctx.GetStub().PutState(UUID, assetJSON)
	if err != nil {
		return "Unable to update asset", err
	}

	return "APIId added to map for user " + UUID, nil
}

func (s *SmartContract) GetAllUsers(ctx contractapi.TransactionContextInterface) ([]*User, error) {
	// range query with empty string for startKey and endKey does an
	// open-ended query of all schemas in the chaincode namespace.
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var UserSamples []*User
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var user map[string]interface{}
		err = json.Unmarshal(queryResponse.Value, &user)
		if err != nil {
			return nil, err
		} else if _, ok := user["UUID"]; ok {
			var userStruct User
			err = json.Unmarshal(queryResponse.Value, &userStruct)
			if err != nil {
				return nil, err
			} else {
				UserSamples = append(UserSamples, &userStruct)
			}
		}
	}

	return UserSamples, nil
}

func (s *SmartContract) GroupExists(ctx contractapi.TransactionContextInterface, GroupId string) (bool, error) {
	assetJSON, err := ctx.GetStub().GetState(GroupId)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}

	if assetJSON != nil {
		var data map[string]interface{}
		err2 := json.Unmarshal(assetJSON, &data)
		if err2 != nil {
			return false, fmt.Errorf("failed to read from world state: %v", err2)
		}
		if err3, ok := data["GroupName"]; ok {
			return assetJSON != nil, nil
		} else {
			return false, fmt.Errorf("failed to read from world state. Hash passed as parameter may correspond to a Schema struct or Data Struc rather than to a Group Struct: %v", err3)
		}
	} else {
		return assetJSON != nil, nil
	}
}

func (s *SmartContract) CreateGroup(ctx contractapi.TransactionContextInterface, GroupName string, Project string, Org string) error {
	//Create a function that checks that a group already exists. Maybe combining GroupName, Group Name and project, and turn that into a Hash? Use the Hash to determine if the group exists.
	GroupId := GroupName + "." + Project + "." + Org

	groupExists, err := s.GroupExists(ctx, GroupId)
	if err != nil {
		return fmt.Errorf("unable to check whether Group exists or not: %v", err)
	}

	if groupExists {
		return fmt.Errorf("the group with name %s already exists", GroupName)
	}

	group := Group{
		GroupName: GroupName,
		UUIDs:     []string{},
		Project:   Project,
		Org:       Org,
		GroupId:   GroupId,
	}

	assetJSON, err := json.Marshal(group)
	if err != nil {
		return err
	}

	err = ctx.GetStub().PutState(group.GroupId, assetJSON)
	if err != nil {
		return fmt.Errorf("failed to create new Group. %v", err)
	}

	fmt.Printf("The Group %v has been created ", group.GroupName)

	return nil
}

func (s *SmartContract) ReadGroup(ctx contractapi.TransactionContextInterface, GroupId string) (*Group, error) {
	exists, err := s.GroupExists(ctx, GroupId)
	if (err != nil) || (!exists) {
		return nil, fmt.Errorf("failed to read Group: % v", err)
	}
	assetJSON, err := ctx.GetStub().GetState(GroupId)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if assetJSON == nil {
		return nil, fmt.Errorf("the Group with Hash %s does not exist", GroupId)
	}

	var group Group
	err = json.Unmarshal(assetJSON, &group)
	if err != nil {
		return nil, err
	}

	return &group, nil
}

func (s *SmartContract) AddUserIDToGroup(ctx contractapi.TransactionContextInterface, UUID string, GroupId string) ([]string, error) {
	group, err := s.ReadGroup(ctx, GroupId)
	if err != nil {
		return nil, fmt.Errorf("read Group function failed excecution: %v", err)
	}

	contained := s.contains(ctx, group.UUIDs, UUID)
	if contained {
		return nil, fmt.Errorf("user %v already contained in Group %v", UUID, GroupId)
	}

	group.UUIDs = append(group.UUIDs, UUID)

	assetJSON, err := json.Marshal(group)
	if err != nil {
		return nil, fmt.Errorf("marshal of Group Struct not done: %v", err)
	}

	err = ctx.GetStub().PutState(GroupId, assetJSON)

	if err != nil {
		return nil, fmt.Errorf("unable to update asset: %v", err)
	}

	return group.UUIDs, nil
}
**/

func (s *SmartContract) LinearSearch(ctx contractapi.TransactionContextInterface, list []string, element string) int {
	for i, n := range list {
		if n == element {
			return i
		}
	}
	return -1
}

func (s *SmartContract) RemoveElement(ctx contractapi.TransactionContextInterface, list []string, element string) []string {
	index := s.LinearSearch(ctx, list, element)
	if index != -1 {
		return append(list[:index])
	} else {
		return list
	}
}

/**func (s *SmartContract) DelUserIDFromGroup(ctx contractapi.TransactionContextInterface, UUID string, Hash string) ([]string, error) {
	group, err := s.ReadGroup(ctx, Hash)
	if err != nil {
		return nil, fmt.Errorf("read Group function failed excecution: %v", err)
	}

	contained := s.contains(ctx, group.UUIDs, UUID)
	if !contained {
		return nil, fmt.Errorf("User %v already removed from Group or unexisting", UUID)
	}

	uuids := group.UUIDs
	uuids = s.RemoveElement(ctx, uuids, UUID)
	group.UUIDs = uuids

	assetJSON, err := json.Marshal(group)
	if err != nil {
		return nil, fmt.Errorf("marshal of Group Struct not done: %v", err)
	}

	err = ctx.GetStub().PutState(Hash, assetJSON)

	if err != nil {
		return nil, fmt.Errorf("unable to update asset: %v", err)
	}

	return group.UUIDs, nil
}

func (s *SmartContract) GetAPIUserByUUID(ctx contractapi.TransactionContextInterface, UUID string) ([]string, error) {
	user, err := s.ReadUser(ctx, UUID)
	if err != nil {
		return nil, fmt.Errorf("failed to read User %v from Wrold State", UUID)
	}
	return user.APIUserId, nil

}
**/

func submittingClientIdentity(ctx contractapi.TransactionContextInterface) (string, error) {
	b64ID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return "", fmt.Errorf("Failed to read clientID: %v", err)
	}
	decodeID, err := base64.StdEncoding.DecodeString(b64ID)
	if err != nil {
		return "", fmt.Errorf("failed to base64 decode clientID: %v", err)
	}
	return string(decodeID), nil
}

func verifyClientOrgMatchesPeerOrg(ctx contractapi.TransactionContextInterface) error {
	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed getting the client's MSPID: %v", err)
	}
	peerMSPID, err := shim.GetMSPID()
	if err != nil {
		return fmt.Errorf("failed getting the peer's MSPID: %v", err)
	}

	if clientMSPID != peerMSPID {
		return fmt.Errorf("client from org %v is not authorized to read or write private data from an org %v peer", clientMSPID, peerMSPID)
	}

	return nil
}

// WriteSchemaToPDC submits a schema to an Org's priva data collection so validations of incoming data can be done.

func (s *SmartContract) WriteSchemaToPDC(ctx contractapi.TransactionContextInterface) error {

	transientAssetJSON, err := s.getTransientMap(ctx)
	if err != nil {
		return fmt.Errorf("error getting transient: %v", err)
	}

	type transientInput struct {
		JsonSchemaContent map[string]interface{} `json:"JsonSchemaContent"`
		SchemaId          string                 `json:"SchemaId"`
		Project           string                 `json:"Project`
	}

	// So far, we've taken what's on the transient dictionary and unmarshal it into the transientInput Struct
	var assetInput transientInput
	err = json.Unmarshal(transientAssetJSON, &assetInput)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %v", err)
	}
	jsonFileContent := assetInput.JsonSchemaContent

	MSP, err := shim.GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get MSPID: %v", err)
	}
	PDC := "_implicit_org_" + MSP
	assetAsBytes, err := ctx.GetStub().GetPrivateData(PDC, assetInput.SchemaId)
	if err != nil {
		return fmt.Errorf("failed to get Schema: %v", err)
	} else if assetAsBytes != nil {
		fmt.Println("Schema already exists: " + assetInput.SchemaId)
		return fmt.Errorf("this Schema already exists: " + assetInput.SchemaId)
	}

	// Get ID of submitting client identity
	clientID, err := submittingClientIdentity(ctx)
	if err != nil {
		return err
	}

	// Verify that the client is submitting request to peer in their organization
	// This is to ensure that a client from another org doesn't attempt to read or
	// write private data from this peer.
	err = verifyClientOrgMatchesPeerOrg(ctx)
	if err != nil {
		return fmt.Errorf("CreateSchema cannot be performed: Error %v", err)
	}

	Schema := PrivateSchemaContent{
		JsonSchemaContent: jsonFileContent,
		SchemaId:          assetInput.SchemaId,
		Project:           assetInput.Project,
	}
	assetJSONasBytes, err := json.Marshal(Schema)
	if err != nil {
		return fmt.Errorf("failed to marshal Schema into JSON: %v", err)
	}

	// Save asset to private data collection
	// Typical logger, logs to stdout/file in the fabric managed docker container, running this chaincode
	// Look for container name like dev-peer0.org1.example.com-{chaincodename_version}-xyz
	log.Printf("WriteSchemaToPDC Put: collection %v, ID %v, owner %v", PDC, assetInput.SchemaId, clientID)

	err = ctx.GetStub().PutPrivateData(PDC, assetInput.SchemaId, assetJSONasBytes)
	if err != nil {
		return fmt.Errorf("failed to put asset into private data collection: %v", err)
	}

	return nil
}

// ReadAsset reads the information from collection
func (s *SmartContract) ReadSchemaFromPDC(ctx contractapi.TransactionContextInterface, SchemaID string) (*Schema, error) {
	MSP, err := shim.GetMSPID()
	if err != nil {
		return nil, fmt.Errorf("failed to get MSPID: %v", err)
	}

	err = verifyClientOrgMatchesPeerOrg(ctx)
	if err != nil {
		return nil, fmt.Errorf("CreateSchema cannot be performed: Error %v", err)
	}

	PDC := "_implicit_org_" + MSP
	log.Printf("ReadSchemaFromPDC: collection %v, ID %v", PDC, SchemaID)
	assetJSON, err := ctx.GetStub().GetPrivateData(PDC, SchemaID) //get the asset from chaincode state
	if err != nil {
		return nil, fmt.Errorf("failed to read Schema: %v", err)
	}

	//No Asset found, return empty response
	if assetJSON == nil {
		log.Printf("%v does not exist in collection %v", SchemaID, PDC)
		return nil, fmt.Errorf("%v does not exist in collection %v", SchemaID, PDC)
	}

	var schema *Schema
	err = json.Unmarshal(assetJSON, &schema)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	return schema, nil

}

func (s *SmartContract) GetAllPDCSchemas(ctx contractapi.TransactionContextInterface) ([]*Schema, error) {

	MSP, err := shim.GetMSPID()
	if err != nil {
		return nil, fmt.Errorf("failed to get MSPID: %v", err)
	}
	PDC := "_implicit_org_" + MSP
	log.Printf("GetAllPDCSchemas: collection %v ", PDC)

	resultsIterator, err := ctx.GetStub().GetPrivateDataByRange(PDC, "", "")

	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	if err != nil {
		return nil, fmt.Errorf("failed to read Schemas: %v", err)
	}

	var schemas []*Schema
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var schema map[string]interface{}
		err = json.Unmarshal(queryResponse.Value, &schema)
		if err != nil {
			return nil, err
		}
		var schemaStruct Schema
		err = json.Unmarshal(queryResponse.Value, &schemaStruct)
		if err != nil {
			return nil, err
		} else {
			schemas = append(schemas, &schemaStruct)
		}
	}

	return schemas, nil
}

func (s *SmartContract) getTransientMap(ctx contractapi.TransactionContextInterface) ([]byte, error) {
	// Get new asset from transient map
	transientMap, err := ctx.GetStub().GetTransient()
	if err != nil {
		return nil, fmt.Errorf("error getting transient: %v", err)
	}
	// Project properties are private, therefore they get passed in transient field, instead of func args
	transientAssetJSON, ok := transientMap["asset_properties"]
	if !ok {
		//log error to stdout
		return nil, fmt.Errorf("asset not found in the transient map input")
	}
	return transientAssetJSON, nil
}

// Could also be called "Create Project"
func (s *SmartContract) writeProjectToPDC(ctx contractapi.TransactionContextInterface) error {

	transientAssetJSON, err := s.getTransientMap(ctx)
	if err != nil {
		return fmt.Errorf("error getting transient: %v", err)
	}

	type transientInput struct {
		OrgName     string `json:OrgName`
		ProjectName string `json:ProjectName`
		AdmninGroup []User `json:AdminGroup`
		UsersGroup  []User `json:UsersGroup`
		ProjectID   string `json:ProjectID`
	}

	var assetInput transientInput
	err = json.Unmarshal(transientAssetJSON, &assetInput)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	assetAsBytes, err := ctx.GetStub().GetPrivateData(PDC2, assetInput.ProjectID)
	if err != nil {
		return fmt.Errorf("failed to get Project: %v", err)
	} else if assetAsBytes != nil {
		fmt.Println("Project already exists: " + assetInput.ProjectID)
		return fmt.Errorf("this Project already exists: " + assetInput.ProjectID)
	}

	// Get ID of submitting client identity
	clientID, err := submittingClientIdentity(ctx)
	if err != nil {
		return err
	}

	// Verify that the client is submitting request to peer in their organization
	// This is to ensure that a client from another org doesn't attempt to read or
	// write private data from this peer.
	err = verifyClientOrgMatchesPeerOrg(ctx)
	if err != nil {
		return fmt.Errorf("CreateSchema cannot be performed: Error %v", err)
	}

	Project := PrivateProjectsContent{
		OrgName:     assetInput.OrgName,
		ProjectName: assetInput.ProjectName,
		//AdminGroup: ,
		//UsersGroup: ,
		ProjectID: assetInput.ProjectID,
	}

	assetJSONasBytes, err := json.Marshal(Project)
	if err != nil {
		return fmt.Errorf("failed to marshal Schema into JSON: %v", err)
	}

	log.Printf("WriteProjectToPDC Put: collection %v, ID %v, owner %v", PDC2, assetInput.ProjectID, clientID)

	err = ctx.GetStub().PutPrivateData(PDC2, assetInput.ProjectID, assetJSONasBytes)
	if err != nil {
		return fmt.Errorf("failed to put asset into private data collection: %v", err)
	}

	return nil
}
