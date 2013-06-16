<?php

namespace Controller\API {

	class OAuth extends \Controller\API {

		function get_username($access_token) {
			$resource = new \Model\OAuth\Resource($access_token);
			return $resource->get_username();
		}

	}

}