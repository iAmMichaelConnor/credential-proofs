const contractPerNetwork = {
  mainnet: 'reclaim-protocol-mainnet.near',
  testnet: 'reclaim-protocol.testnet',
};

export const NetworkId = 'testnet';
export const ReclaimNearContract = contractPerNetwork[NetworkId];

export const SMOKE_PROOF = {
    "identifier": "0x9ec8f9f52623234433ce5ea0cc0f5aac0dfbeef553e68d2d403633bd9192e365",
    "claimData": {
      "provider": "http",
      "parameters": "{\"body\":\"\",\"geoLocation\":\"in\",\"method\":\"GET\",\"paramValues\":{\"CLAIM_DATA\":\"76561199614512180\"},\"responseMatches\":[{\"type\":\"contains\",\"value\":\"_steamid\\\">Steam ID: {{CLAIM_DATA}}</div>\"}],\"responseRedactions\":[{\"jsonPath\":\"\",\"regex\":\"_steamid\\\">Steam ID: (.*)</div>\",\"xPath\":\"id(\\\"responsive_page_template_content\\\")/div[@class=\\\"page_header_ctn\\\"]/div[@class=\\\"page_content\\\"]/div[@class=\\\"youraccount_steamid\\\"]\"}],\"url\":\"https://store.steampowered.com/account/\"}",
      "owner": "0xa1b6e6ffb85df5bdf78e6558d3224ab87f7cc4c7",
      "timestampS": 1717053708,
      "context": "{\"contextAddress\":\"user's address\",\"contextMessage\":\"for acmecorp.com on 1st january\",\"extractedParameters\":{\"CLAIM_DATA\":\"76561199614512180\"},\"providerHash\":\"0x5f5312e27124dc7605f70a7d884e169049679b93f91c137b4d18a8569d825900\"}",
      "identifier": "0x9ec8f9f52623234433ce5ea0cc0f5aac0dfbeef553e68d2d403633bd9192e365",
      "epoch": 1
    },
    "signatures": [
      "0xcbad077154cc5c8e494576d4336f57972f7412058c1a637e05832c6bdabd018f4da18ad973f29553921d7d030370032addac1159146b77ec6cc5dab4133ffec01c"
    ],
    "witnesses": [
      {
        "id": "0x244897572368eadf65bfbc5aec98d8e5443a9072",
        "url": "https://reclaim-node.questbook.app"
      }
    ]
  }
